import asyncio
import websockets
import json
import sqlite3
import datetime
import hashlib
import os
import time
import logging
import http

logging.basicConfig(level=logging.WARNING, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("kavaxs")

DB_PATH = "kavaxs_auth.db"
ADMIN_PHONE = os.environ.get("KAVAXS_ADMIN", "+375259178812")
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

async def health_check(path, request_headers):
    if path == "/healthz":
        return http.HTTPStatus.OK, [], b"OK\n"
    return None

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

def get_user_transactions(phone):
    c.execute("SELECT amount, reason, date FROM transactions WHERE phone=? ORDER BY id DESC LIMIT 20", (phone,))
    return [{"amount": r[0], "reason": r[1], "date": r[2]} for r in c.fetchall()]

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
                username = (data.get("username") or "").strip().lower().replace("@", "")
                email = (data.get("email") or "").strip()
                if not phone.startswith("+") or len(phone) < 8 or len(pwd) < 6 or not name:
                    await send(ws, {"type": "error", "msg": "Неверные данные"}); continue
                async with db_lock:
                    try:
                        c.execute("INSERT INTO users (phone,password,name,username,email,ip) VALUES (?,?,?,?,?,?)", (phone, hash_pwd(pwd), name, username, email, client_ip))
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
                async with db_lock:
                    c.execute("UPDATE users SET ip=? WHERE phone=?", (client_ip, phone))
                    conn.commit()
                user_data = get_user_data(phone, phone); user_data["type"] = "auth_ok"; user_data["gifts"] = get_user_gifts(phone); user_data["posts"] = get_user_posts(phone)
                await send(ws, user_data)

            # --- ПОИСК ---
            elif t == "search":
                if not client_phone: continue
                query = (data.get("query") or "").strip()
                if not query: continue
                async with db_lock:
                    c.execute("SELECT phone FROM users WHERE phone LIKE ? OR username LIKE ? OR name LIKE ? LIMIT 20", (f"%{query}%", f"%{query}%", f"%{query}%"))
                    rows = c.fetchall()
                    results = []
                    for r in rows:
                        u = get_user_data(r[0], client_phone)
                        if u and u["phone"] != client_phone: # не показываем себя
                            results.append(u)
                await send(ws, {"type": "search_result", "results": results})
            # -------------

            elif t == "get_profile":
                target = data.get("target")
                async with db_lock:
                    user_data = get_user_data(target, client_phone)
                    gifts = get_user_gifts(target)
                    posts = get_user_posts(target)
                if user_data:
                    user_data["gifts"] = gifts
                    user_data["posts"] = posts
                    await send(ws, {"type": "user_profile", "user": user_data})

            elif t == "update_media":
                if not client_phone: continue
                av, bg = data.get("avatar"), data.get("bg")
                async with db_lock:
                    if av is not None: c.execute("UPDATE users SET avatar=? WHERE phone=?", (av, client_phone))
                    if bg is not None: c.execute("UPDATE users SET bg=? WHERE phone=?", (bg, client_phone))
                    conn.commit()
                await send(ws, {"type": "media_ok"})

            elif t == "update_bio":
                if not client_phone: continue
                new_bio = data.get("bio", "")
                async with db_lock:
                    c.execute("UPDATE users SET bio=? WHERE phone=?", (new_bio, client_phone))
                    conn.commit()
                await send(ws, {"type": "bio_ok", "bio": new_bio})

            elif t == "add_post":
                if not client_phone: continue
                image = data.get("image")
                async with db_lock:
                    c.execute("INSERT INTO posts (phone, image, date) VALUES (?,?,?)", (client_phone, image, now_str()))
                    conn.commit()
                    posts = get_user_posts(client_phone)
                await send(ws, {"type": "posts_updated", "posts": posts})

            elif t == "admin_set_fake":
                if client_phone == ADMIN_PHONE:
                    target = data.get("target")
                    fake_num = data.get("fake_phone")
                    async with db_lock:
                        c.execute("UPDATE users SET fake_phone=? WHERE phone=?", (fake_num, target))
                        conn.commit()
                    await send(ws, {"type": "admin_ok", "msg": "Фейковый номер установлен"})

            elif t == "admin_get_users":
                if client_phone == ADMIN_PHONE:
                    async with db_lock:
                        c.execute("SELECT phone, name, is_banned, is_premium, ip, kstars FROM users LIMIT 50")
                        users = [{"phone": r[0], "name": r[1], "is_banned": r[2], "is_premium": r[3], "ip": r[4], "kstars": r[5]} for r in c.fetchall()]
                    await send(ws, {"type": "admin_users_list", "users": users})

            elif t == "admin_unban":
                if client_phone == ADMIN_PHONE:
                    target = data.get("target")
                    async with db_lock:
                        c.execute("UPDATE users SET is_banned=0 WHERE phone=?", (target,))
                        conn.commit()
                    await send(ws, {"type": "admin_ok", "msg": "Разбанен!"})

            elif t == "admin_ban":
                if client_phone == ADMIN_PHONE:
                    target, ban_type = data.get("target"), data.get("ban_type")
                    kick = set()
                    async with db_lock:
                        if ban_type == "phone":
                            c.execute("UPDATE users SET is_banned=1 WHERE phone=?", (target,)); kick.add(target)
                        elif ban_type == "ip":
                            c.execute("SELECT phone FROM users WHERE ip=(SELECT ip FROM users WHERE phone=?)", (target,))
                            kick = {r[0] for r in c.fetchall()}
                            c.execute("UPDATE users SET is_banned=1 WHERE ip=(SELECT ip FROM users WHERE phone=?)", (target,))
                        conn.commit()
                    await send(ws, {"type": "admin_ok", "msg": "Забанен"})
                    for client, info in list(connected_clients.items()):
                        if info["phone"] in kick:
                            await send(client, {"type": "force_logout"})
                            connected_clients.pop(client, None)

            elif t == "admin_give_kstars":
                if client_phone == ADMIN_PHONE:
                    target = data.get("target")
                    amount = data.get("amount", 100)
                    async with db_lock:
                        c.execute("UPDATE users SET kstars = kstars + ? WHERE phone=?", (amount, target))
                        conn.commit()
                    await send(ws, {"type": "admin_ok", "msg": f"Начислено {amount} K-Star"})

            elif t == "admin_broadcast":
                if client_phone == ADMIN_PHONE:
                    text = data.get("text")
                    payload = {"type": "msg", "sender": "admin", "name": "Админ", "target": "general", "text": text, "date": now_str()}
                    for client in list(connected_clients.keys()): await send(client, payload)

            elif t == "admin_give_gift":
                if client_phone == ADMIN_PHONE:
                    target = data.get("target")
                    gift_type = data.get("gift_type")
                    async with db_lock:
                        c.execute("INSERT INTO gifts (sender, target, gift_type, price, date) VALUES (?,?,?,?,?)", (ADMIN_PHONE, target, gift_type, 0, now_str()))
                        conn.commit()
                    await send(ws, {"type": "admin_ok", "msg": "Подарок выдан"})

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

            elif t == "get_chat_history":
                if not client_phone: continue
                target = data.get("target")
                async with db_lock:
                    c.execute("""SELECT id, sender, name, text, date, reply_to_id, forward_from, media_type, media_data FROM messages 
                                 WHERE ((sender=? AND target=?) OR (sender=? AND target=?)) AND is_deleted=0
                                 ORDER BY id ASC LIMIT 100""", (client_phone, target, target, client_phone))
                    rows = c.fetchall()
                msgs = []
                for r in rows:
                    msg_id = r[0]
                    c.execute("SELECT emoji, COUNT(*) FROM reactions WHERE msg_id=? GROUP BY emoji", (msg_id,))
                    reacts = {row[0]: row[1] for row in c.fetchall()}
                    msgs.append({"id": r[0], "sender": r[1], "name": r[2], "text": r[3], "date": r[4], "reply_to_id": r[5], "forward_from": r[6], "media_type": r[7], "media_data": r[8], "reactions": reacts})
                await send(ws, {"type": "chat_history_result", "target": target, "messages": msgs})

            elif t == "delete_msg":
                if not client_phone: continue
                msg_id, target = data.get("msg_id"), data.get("target")
                async with db_lock:
                    c.execute("UPDATE messages SET is_deleted=1 WHERE id=? AND sender=?", (msg_id, client_phone))
                    conn.commit()
                payload = {"type": "msg_deleted", "msg_id": msg_id, "target": target}
                if target == "general":
                    for client in list(connected_clients.keys()): await send(client, payload)
                else:
                    await broadcast_to_phones({client_phone, target}, payload)

            elif t == "add_reaction":
                if not client_phone: continue
                msg_id, emoji, target = data.get("msg_id"), data.get("emoji"), data.get("target")
                async with db_lock:
                    c.execute("DELETE FROM reactions WHERE msg_id=? AND phone=?", (msg_id, client_phone))
                    c.execute("INSERT INTO reactions (msg_id, phone, emoji) VALUES (?,?,?)", (msg_id, client_phone, emoji))
                    conn.commit()
                    c.execute("SELECT emoji, COUNT(*) FROM reactions WHERE msg_id=? GROUP BY emoji", (msg_id,))
                    reacts = {row[0]: row[1] for row in c.fetchall()}
                payload = {"type": "reaction_updated", "msg_id": msg_id, "reactions": reacts, "target": target}
                if target == "general":
                    for client in list(connected_clients.keys()): await send(client, payload)
                else:
                    await broadcast_to_phones({client_phone, target}, payload)

            elif t == "get_history":
                if not client_phone: continue
                async with db_lock:
                    c.execute("""SELECT target, MAX(date) d FROM history WHERE phone=? GROUP BY target
                                 UNION ALL SELECT phone, MAX(date) d FROM history WHERE target=? GROUP BY phone
                                 ORDER BY d DESC LIMIT 20""", (client_phone, client_phone))
                    rows = c.fetchall()
                hist = []
                seen = set()
                for tgt, _ in rows:
                    if tgt in seen or tgt == "general": continue
                    seen.add(tgt)
                    async with db_lock:
                        user_data = get_user_data(tgt, client_phone)
                    if user_data: hist.append(user_data)
                await send(ws, {"type": "history_result", "history": hist})

            elif t == "buy_gift":
                if not client_phone: continue
                gift_type = data.get("gift_type")
                price = int(data.get("price", 10))
                async with db_lock:
                    c.execute("SELECT kstars FROM users WHERE phone=?", (client_phone,))
                    bal = c.fetchone()[0]
                    if bal < price:
                        await send(ws, {"type": "error", "msg": f"Недостаточно K-Star! Нужно {price}."}); continue
                    c.execute("UPDATE users SET kstars = kstars - ? WHERE phone=?", (price, client_phone))
                    c.execute("INSERT INTO gifts (sender, target, gift_type, price, date) VALUES (?,?,?,?,?)", (client_phone, client_phone, gift_type, price, now_str()))
                    c.execute("INSERT INTO transactions (phone, amount, reason, date) VALUES (?, ?, ?, ?)", (client_phone, -price, f"Покупка NFT: {gift_type}", now_str()))
                    conn.commit()
                    c.execute("SELECT kstars FROM users WHERE phone=?", (client_phone,))
                    new_bal = c.fetchone()[0]
                    gifts = get_user_gifts(client_phone)
                await send(ws, {"type": "gift_ok", "msg": "NFT добавлен!", "kstars": new_bal, "gifts": gifts})

            elif t == "sell_gift":
                if not client_phone: continue
                gift_id = data.get("gift_id")
                async with db_lock:
                    c.execute("SELECT price FROM gifts WHERE id=? AND target=?", (gift_id, client_phone))
                    gift_row = c.fetchone()
                    if not gift_row:
                        await send(ws, {"type": "error", "msg": "Подарок не найден"}); continue
                    price = gift_row[0]
                    c.execute("UPDATE gifts SET is_sold=1 WHERE id=?", (gift_id,))
                    c.execute("UPDATE users SET kstars = kstars + ? WHERE phone=?", (price, client_phone))
                    c.execute("INSERT INTO transactions (phone, amount, reason, date) VALUES (?, ?, ?, ?)", (client_phone, price, f"Продажа NFT", now_str()))
                    conn.commit()
                    c.execute("SELECT kstars FROM users WHERE phone=?", (client_phone,))
                    new_bal = c.fetchone()[0]
                    gifts = get_user_gifts(client_phone)
                await send(ws, {"type": "gift_sold", "msg": "Подарок продан", "kstars": new_bal, "gifts": gifts})

            elif t == "send_gift":
                if not client_phone: continue
                target = data.get("target")
                gift_type = data.get("gift_type")
                price = int(data.get("price", 10))
                async with db_lock:
                    c.execute("SELECT kstars FROM users WHERE phone=?", (client_phone,))
                    bal = c.fetchone()[0]
                    if bal < price:
                        await send(ws, {"type": "error", "msg": f"Недостаточно K-Star!"}); continue
                    c.execute("UPDATE users SET kstars = kstars - ? WHERE phone=?", (price, client_phone))
                    c.execute("INSERT INTO gifts (sender, target, gift_type, price, date) VALUES (?,?,?,?,?)", (client_phone, target, gift_type, price, now_str()))
                    c.execute("INSERT INTO transactions (phone, amount, reason, date) VALUES (?, ?, ?, ?)", (client_phone, -price, f"Подарок: {gift_type}", now_str()))
                    conn.commit()
                    c.execute("SELECT name, avatar FROM users WHERE phone=?", (client_phone,))
                    s_name, s_av = c.fetchone()
                
                payload = {"type": "gift_received", "sender": client_phone, "sender_name": s_name, "sender_avatar": s_av, "target": target, "gift": {"type": gift_type, "price": price, "sender_name": s_name, "sender_avatar": s_av}}
                await send(ws, {"type": "gift_ok", "msg": "Подарок отправлен!"})
                await broadcast_to_phones({target}, payload)

            elif t == "get_transactions":
                if not client_phone: continue
                txs = get_user_transactions(client_phone)
                await send(ws, {"type": "transactions_result", "transactions": txs})

    except websockets.exceptions.ConnectionClosed:
        pass
    finally:
        if ws in connected_clients:
            del connected_clients[ws]

async def main():
    async with websockets.serve(handler, HOST, PORT, process_request=health_check):
        log.warning(f"KavaxsGram server on ws://{HOST}:{PORT}")
        await asyncio.Future()

if __name__ == "__main__":
    asyncio.run(main())
