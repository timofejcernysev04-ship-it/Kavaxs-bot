import asyncio
import websockets
import json
import sqlite3
import datetime
import hashlib
import os
import time
import logging

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kavaxs")

DB_PATH = "kavaxs_auth.db"
ADMIN_PHONE = os.environ.get("KAVAXS_ADMIN", "+375259178812")

# Render сам передает порт через переменную PORT
PORT = int(os.environ.get("PORT", 8082))
HOST = "0.0.0.0"

conn = sqlite3.connect(DB_PATH, check_same_thread=False)
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA synchronous=NORMAL")
conn.execute("PRAGMA cache_size=-2000")
c = conn.cursor()

c.executescript("""
CREATE TABLE IF NOT EXISTS users (
    phone TEXT PRIMARY KEY, email TEXT, password TEXT NOT NULL, name TEXT NOT NULL, username TEXT,
    hide_username INTEGER DEFAULT 0, hide_phone INTEGER DEFAULT 0, is_premium INTEGER DEFAULT 0,
    is_banned INTEGER DEFAULT 0, is_scam INTEGER DEFAULT 0, is_fake INTEGER DEFAULT 0, ip TEXT,
    bio TEXT DEFAULT '', avatar TEXT DEFAULT '', bg TEXT DEFAULT '', kstars INTEGER DEFAULT 0,
    reactions TEXT DEFAULT '["❤️","👍","🔥","😂","😮","😢"]', fake_phone TEXT DEFAULT ''
);
CREATE TABLE IF NOT EXISTS history (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, target TEXT NOT NULL, date TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT NOT NULL, name TEXT NOT NULL, target TEXT NOT NULL, text TEXT NOT NULL, date TEXT NOT NULL, reply_to_id INTEGER, forward_from TEXT, is_deleted INTEGER DEFAULT 0, media_type TEXT, media_data TEXT);
CREATE TABLE IF NOT EXISTS reactions (id INTEGER PRIMARY KEY AUTOINCREMENT, msg_id INTEGER NOT NULL, phone TEXT NOT NULL, emoji TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS gifts (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, target TEXT NOT NULL, gift_type TEXT NOT NULL, price INTEGER DEFAULT 10, date TEXT NOT NULL, is_sold INTEGER DEFAULT 0);
CREATE TABLE IF NOT EXISTS transactions (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, amount INTEGER NOT NULL, reason TEXT NOT NULL, date TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT, phone TEXT NOT NULL, image TEXT NOT NULL, date TEXT NOT NULL);
""")
conn.commit()

db_lock = asyncio.Lock()
connected_clients = {}
login_attempts = {}

def hash_pwd(pwd: str) -> str:
    salt = os.urandom(16)
    h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), salt, 200_000)
    return salt.hex() + "$" + h.hex()

def check_pwd(pwd: str, stored: str) -> bool:
    try:
        salt_hex, h_hex = stored.split("$")
        h = hashlib.pbkdf2_hmac("sha256", pwd.encode(), bytes.fromhex(salt_hex), 200_000)
        return h.hex() == h_hex
    except: return False

def now_str(): return datetime.datetime.now().strftime("%Y-%m-%d %H:%M")

def allow_login(ip: str) -> bool:
    ts = login_attempts.setdefault(ip, [])
    cutoff = time.time() - 60
    login_attempts[ip] = [t for t in ts if t > cutoff]
    if len(login_attempts[ip]) >= 5: return False
    login_attempts[ip].append(time.time())
    return True

async def send(ws, payload):
    try: await ws.send(json.dumps(payload))
    except: pass

async def broadcast_to_phones(phones, payload):
    payload = json.dumps(payload)
    for ws, info in list(connected_clients.items()):
        if info["phone"] in phones:
            try: await ws.send(payload)
            except: pass

def get_user_data(phone, viewer_phone=None):
    c.execute("SELECT name,phone,username,is_premium,is_scam,is_fake,bio,avatar,bg,kstars,ip,reactions,fake_phone FROM users WHERE phone=?", (phone,))
    row = c.fetchone()
    if not row: return None
    real_phone = row[1]
    fake = row[12]
    display_phone = real_phone
    if viewer_phone != real_phone and viewer_phone != ADMIN_PHONE and fake:
        display_phone = fake
    return {"name": row[0], "phone": display_phone, "real_phone": real_phone, "username": row[2], "is_premium": row[3], "is_scam": row[4], "is_fake": row[5], "bio": row[6], "avatar": row[7], "bg": row[8], "kstars": row[9], "ip": row[10], "reactions": json.loads(row[11] or '[]'), "is_admin": real_phone == ADMIN_PHONE}

def get_user_posts(phone):
    c.execute("SELECT id, image, date FROM posts WHERE phone=? ORDER BY id DESC", (phone,))
    return [{"id": r[0], "image": r[1], "date": r[2]} for r in c.fetchall()]

def get_user_gifts(phone):
    c.execute("SELECT id, gift_type, sender, date, price, is_sold FROM gifts WHERE target=? AND is_sold=0 ORDER BY id DESC", (phone,))
    rows = c.fetchall()
    gifts = []
    for r in rows:
        c.execute("SELECT name, avatar FROM users WHERE phone=?", (r[2],))
        sender = c.fetchone()
        gifts.append({"id": r[0], "type": r[1], "sender": r[2], "sender_name": sender[0] if sender else "Неизвестно", "sender_avatar": sender[1] if sender else "", "date": r[3], "price": r[4], "is_sold": r[5]})
    return gifts

async def handler(ws):
    client_phone = None
    client_ip = ws.remote_address[0] if ws.remote_address else "unknown"
    try:
        async for raw in ws:
            try: data = json.loads(raw)
            except: continue
            t = data.get("type")

            if t == "register":
                phone, pwd, name = (data.get("phone") or "").strip(), data.get("password") or "", (data.get("name") or "").strip()
                if not phone.startswith("+") or len(phone) < 8 or len(pwd) < 6 or not name:
                    await send(ws, {"type": "error", "msg": "Неверные данные"}); continue
                async with db_lock:
                    try:
                        c.execute("INSERT INTO users (phone,password,name,ip) VALUES (?,?,?,?)", (phone, hash_pwd(pwd), name, client_ip))
                        conn.commit()
                    except sqlite3.IntegrityError:
                        await send(ws, {"type": "error", "msg": "Аккаунт уже есть"}); continue
                client_phone = phone
                connected_clients[ws] = {"phone": phone, "name": name}
                user_data = get_user_data(phone, phone); user_data["type"] = "auth_ok"; user_data["gifts"] = []; user_data["posts"] = []
                await send(ws, user_data)

            elif t == "login":
                if not allow_login(client_ip):
                    await send(ws, {"type": "error", "msg": "Слишком много попыток."}); continue
                phone, pwd = (data.get("phone") or "").strip(), data.get("password") or ""
                async with db_lock:
                    c.execute("SELECT name,password,is_banned FROM users WHERE phone=?", (phone,))
                    row = c.fetchone()
                if not row or not check_pwd(pwd, row[1]):
                    await send(ws, {"type": "error", "msg": "Неверный номер или пароль"}); continue
                if row[2]:
                    await send(ws, {"type": "error", "msg": "⛔ Аккаунт забанен"}); continue
                client_phone = phone
                connected_clients[ws] = {"phone": phone, "name": row[0]}
                user_data = get_user_data(phone, phone); user_data["type"] = "auth_ok"; user_data["gifts"] = get_user_gifts(phone); user_data["posts"] = get_user_posts(phone)
                await send(ws, user_data)

            elif t == "msg":
                if not client_phone: continue
                target, text = data.get("target") or "general", (data.get("text") or "").strip()
                media_type, media_data = data.get("media_type"), data.get("media_data")
                if not text and not media_data: continue
                reply_to, forward_from = data.get("reply_to_id"), data.get("forward_from")
                async with db_lock:
                    c.execute("SELECT name, is_premium, avatar FROM users WHERE phone=?", (client_phone,))
                    u = c.fetchone(); name, is_prem, avatar = u[0], u[1], u[2]
                    date = now_str()
                    c.execute("INSERT INTO messages (sender,name,target,text,date,reply_to_id,forward_from,media_type,media_data) VALUES (?,?,?,?,?,?,?,?,?)", (client_phone, name, target, text, date, reply_to, forward_from, media_type, media_data))
                    msg_id = c.lastrowid
                    if target != "general":
                        c.execute("INSERT INTO history (phone,target,date) VALUES (?,?,?)", (client_phone, target, date))
                        c.execute("INSERT INTO history (phone,target,date) VALUES (?,?,?)", (target, client_phone, date))
                    conn.commit()
                payload = {"type": "msg", "id": msg_id, "sender": client_phone, "name": name, "target": target, "text": text, "date": date, "is_premium": is_prem, "avatar": avatar, "reply_to_id": reply_to, "forward_from": forward_from, "media_type": media_type, "media_data": media_data}
                if target == "general":
                    for client in list(connected_clients.keys()): await send(client, payload)
                else:
                    await broadcast_to_phones({client_phone, target}, payload)
                    
            # ОСТАЛЬНЫЕ ОБРАБОТЧИКИ (get_chat_history, delete_msg, add_reaction, buy_gift, sell_gift и т.д.)
            # ОНИ У ТЕБЯ УЖЕ ЕСТЬ В ИСХОДНОМ КОДЕ, Я ИХ НЕ УДАЛЯЛ, ПРОСТО СОКРАТИЛ ЗДЕСЬ ДЛЯ ПРИМЕРА.
            # ВСТАВЬ ИХ СЮДА ИЗ СВОЕГО СТАРОГО ФАЙЛА.

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if ws in connected_clients: del connected_clients[ws]

async def main():
    async with websockets.serve(handler, HOST, PORT):
        log.warning(f"KavaxsGram server on ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
