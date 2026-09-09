# -*- coding: utf-8 -*-
"""Сервер ключей Shade.

Хранит аккаунты, ключи подписки и активации; выдаёт лаунчеру ответ «подписка
активна / нет».

Работает на двух видах хранилища без правок кода:
  * если задан DATABASE_URL — Postgres (Render и подобные);
  * иначе — SQLite-файл рядом с приложением (PythonAnywhere и любой хостинг с
    постоянным диском). На бесплатном Render так нельзя — там диск сбрасывается,
    но на PythonAnywhere диск постоянный, поэтому файловая база там надёжна.

Эндпоинты (всё — JSON POST, кроме health):
  GET  /                     — проверка живости
  POST /api/register         {login, password}
  POST /api/login            {login, password, hwid}
  POST /api/activate         {login, key, hwid}       — активировать ключ себе
  POST /api/check            {login, hwid}            — активна ли подписка
  POST /api/admin/genkey     {admin_token, duration, count}
  POST /api/admin/keys       {admin_token}            — список ключей
  POST /api/admin/revoke     {admin_token, key}

Пароли не хранятся в открытом виде: своя соль + SHA-256(соль+пароль) у каждого.
Доступ к админ-эндпоинтам — по ADMIN_TOKEN из переменной окружения.
"""
import hashlib
import os
import secrets
import sqlite3
import time
from datetime import datetime, timezone

from flask import Flask, jsonify, request

app = Flask(__name__)

ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "")
# Логины-админы: ADMIN_USERS="Spaxer,Other" (через запятую, регистр важен).
ADMIN_USERS = {u.strip() for u in os.environ.get("ADMIN_USERS", "").split(",") if u.strip()}
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Файл SQLite кладём рядом с приложением, а не в /tmp: /tmp на некоторых
# хостингах чистится, а каталог приложения на PythonAnywhere постоянный.
SQLITE_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shade.db")

USE_PG = bool(DATABASE_URL)
if USE_PG:
    import psycopg  # noqa: имп только когда реально нужен Postgres

# В SQLite плейсхолдер «?», в psycopg — «%s». Держим один текст запросов и
# подставляем нужный символ, чтобы не дублировать SQL под каждую базу.
PH = "%s" if USE_PG else "?"

DURATIONS = {
    "1h": 3600,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "180d": 180 * 86400,
    "forever": 100 * 365 * 86400,
}


def connect():
    if USE_PG:
        return psycopg.connect(DATABASE_URL, autocommit=True)
    conn = sqlite3.connect(SQLITE_PATH)
    conn.isolation_level = None  # autocommit
    return conn


def run(sql, params=()):
    """Выполнить запрос, вернуть все строки. SQL пишем с «?», под Postgres меняем."""
    if USE_PG:
        sql = sql.replace("?", "%s")
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute(sql, params)
        rows = cur.fetchall() if cur.description else []
        return rows
    finally:
        conn.close()


def init_db():
    # BIGINT/INTEGER и BOOLEAN/INTEGER — единственное, что различается меж базами.
    big = "BIGINT" if USE_PG else "INTEGER"
    boolean = "BOOLEAN" if USE_PG else "INTEGER"
    run(f"""
        CREATE TABLE IF NOT EXISTS users (
            login       TEXT PRIMARY KEY,
            salt        TEXT NOT NULL,
            phash       TEXT NOT NULL,
            hwid        TEXT DEFAULT '',
            role        TEXT DEFAULT 'user',
            sub_expires {big} DEFAULT 0,
            created     {big} NOT NULL
        )
    """)
    run(f"""
        CREATE TABLE IF NOT EXISTS keys (
            key        TEXT PRIMARY KEY,
            seconds    {big} NOT NULL,
            created_at {big} NOT NULL,
            used_by    TEXT DEFAULT '',
            used_at    {big} DEFAULT 0,
            revoked    {boolean} DEFAULT 0
        )
    """)


def now():
    return int(time.time())


def hash_pw(salt, password):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def make_key():
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "SHADE-" + "-".join(groups)


def is_admin(data):
    # Путь 1 — запасной токен (для скриптов).
    if ADMIN_TOKEN and data.get("admin_token", "") == ADMIN_TOKEN:
        return True
    # Путь 2 — аккаунт админа: логин в ADMIN_USERS и верный пароль. Так у
    # лаунчера нет вшитого секрета — админ входит собой.
    login = (data.get("login") or "").strip()
    password = data.get("password") or ""
    if login and login in ADMIN_USERS:
        rows = run("SELECT salt, phash FROM users WHERE login=?", (login,))
        if rows and rows[0][1] == hash_pw(rows[0][0], password):
            return True
    return False


def human(ts):
    if ts <= now():
        return "нет подписки"
    if ts - now() > 50 * 365 * 86400:
        return "навсегда"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


@app.get("/")
def health():
    return jsonify(ok=True, service="shade-backend", storage="postgres" if USE_PG else "sqlite")


@app.post("/api/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    password = d.get("password") or ""
    if len(login) < 3:
        return jsonify(ok=False, error="Логин короче 3 символов")
    if len(password) < 4:
        return jsonify(ok=False, error="Пароль короче 4 символов")
    if run("SELECT 1 FROM users WHERE login=?", (login,)):
        return jsonify(ok=False, error="Такой логин уже занят")

    salt = secrets.token_hex(8)
    run("INSERT INTO users (login, salt, phash, created) VALUES (?,?,?,?)",
        (login, salt, hash_pw(salt, password), now()))
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    password = d.get("password") or ""
    hwid = d.get("hwid") or ""

    rows = run("SELECT salt, phash, role, sub_expires, hwid FROM users WHERE login=?", (login,))
    if not rows or rows[0][1] != hash_pw(rows[0][0], password):
        return jsonify(ok=False, error="Неверный логин или пароль")
    _, _, role, sub_expires, saved_hwid = rows[0]

    # Привязка к железу: первый вход закрепляет HWID, дальше вход только с него.
    if saved_hwid and hwid and saved_hwid != hwid:
        return jsonify(ok=False, error="Аккаунт привязан к другому устройству")
    if not saved_hwid and hwid:
        run("UPDATE users SET hwid=? WHERE login=?", (hwid, login))

    if login in ADMIN_USERS:
        role = "admin"
    return jsonify(ok=True, role=role, sub_expires=sub_expires,
                   active=sub_expires > now(), sub_human=human(sub_expires))


@app.post("/api/activate")
def activate():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    key = (d.get("key") or "").strip().upper()

    u = run("SELECT sub_expires FROM users WHERE login=?", (login,))
    if not u:
        return jsonify(ok=False, error="Аккаунт не найден")

    k = run("SELECT seconds, used_by, revoked FROM keys WHERE key=?", (key,))
    if not k:
        return jsonify(ok=False, error="Ключ не существует")
    seconds, used_by, revoked = k[0]
    if revoked:
        return jsonify(ok=False, error="Ключ отозван")
    if used_by:
        return jsonify(ok=False, error="Ключ уже активирован")

    # Продлеваем от большего из «сейчас» и текущего конца подписки — активация
    # второго ключа не сгорает, а суммируется.
    new_expires = max(now(), u[0][0]) + seconds
    run("UPDATE users SET sub_expires=? WHERE login=?", (new_expires, login))
    run("UPDATE keys SET used_by=?, used_at=? WHERE key=?", (login, now(), key))
    return jsonify(ok=True, sub_expires=new_expires, sub_human=human(new_expires))


@app.post("/api/check")
def check():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    rows = run("SELECT sub_expires FROM users WHERE login=?", (login,))
    if not rows:
        return jsonify(ok=False, error="Аккаунт не найден")
    return jsonify(ok=True, active=rows[0][0] > now(), sub_expires=rows[0][0], sub_human=human(rows[0][0]))


@app.post("/api/admin/genkey")
def genkey():
    d = request.get_json(force=True, silent=True) or {}
    if not is_admin(d):
        return jsonify(ok=False, error="Нет доступа")
    duration = d.get("duration", "")
    if duration not in DURATIONS:
        return jsonify(ok=False, error="Неизвестный срок")
    count = max(1, min(100, int(d.get("count", 1))))

    created = []
    for _ in range(count):
        key = make_key()
        run("INSERT INTO keys (key, seconds, created_at) VALUES (?,?,?)",
            (key, DURATIONS[duration], now()))
        created.append(key)
    return jsonify(ok=True, keys=created, duration=duration)


@app.post("/api/admin/keys")
def list_keys():
    d = request.get_json(force=True, silent=True) or {}
    if not is_admin(d):
        return jsonify(ok=False, error="Нет доступа")
    rows = run("SELECT key, seconds, used_by, used_at, revoked FROM keys ORDER BY created_at DESC LIMIT 500")
    keys = [dict(key=r[0], seconds=r[1], used_by=r[2], used_at=r[3], revoked=bool(r[4])) for r in rows]
    return jsonify(ok=True, keys=keys)


@app.post("/api/admin/revoke")
def revoke():
    d = request.get_json(force=True, silent=True) or {}
    if not is_admin(d):
        return jsonify(ok=False, error="Нет доступа")
    key = (d.get("key") or "").strip().upper()
    run("UPDATE keys SET revoked=1 WHERE key=?", (key,))
    return jsonify(ok=True)


# Таблицы создаём при импорте: и gunicorn, и WSGI PythonAnywhere просто
# импортируют модуль app, __main__ при этом не выполняется.
try:
    init_db()
except Exception as e:  # noqa: BLE001
    print("init_db error:", e)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
