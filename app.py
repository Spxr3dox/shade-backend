# -*- coding: utf-8 -*-
"""Сервер ключей Shade.

Хранит аккаунты, ключи подписки и активации; выдаёт лаунчеру ответ «подписка
активна / нет». Рассчитан на бесплатный Render: данные лежат в Postgres (его
поднимает render.yaml), а НЕ в файле — у бесплатного web-сервиса диск сбрасывается
при каждом перезапуске, и файловая база потеряла бы все ключи.

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
import time
from datetime import datetime, timezone

import psycopg
from flask import Flask, jsonify, request

app = Flask(__name__)

# Токен админки. На Render задаётся переменной окружения; локально — заглушка,
# которую НЕЛЬЗЯ оставлять в проде (её видно в коде).
ADMIN_TOKEN = os.environ.get("ADMIN_TOKEN", "change-me-local-only")
DATABASE_URL = os.environ.get("DATABASE_URL", "")

# Сроки ключей. "forever" — 100 лет, чтобы не городить отдельную ветку с NULL.
DURATIONS = {
    "1h": 3600,
    "7d": 7 * 86400,
    "30d": 30 * 86400,
    "90d": 90 * 86400,
    "180d": 180 * 86400,
    "forever": 100 * 365 * 86400,
}


def db():
    # psycopg сам переиспользует пул на уровне драйвера; для нашего объёма
    # хватает соединения на запрос — Render Postgres это выдерживает.
    return psycopg.connect(DATABASE_URL, autocommit=True)


def init_db():
    with db() as conn, conn.cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                login       TEXT PRIMARY KEY,
                salt        TEXT NOT NULL,
                phash       TEXT NOT NULL,
                hwid        TEXT DEFAULT '',
                role        TEXT DEFAULT 'user',
                sub_expires BIGINT DEFAULT 0,
                created     BIGINT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS keys (
                key        TEXT PRIMARY KEY,
                seconds    BIGINT NOT NULL,
                created_at BIGINT NOT NULL,
                used_by    TEXT DEFAULT '',
                used_at    BIGINT DEFAULT 0,
                revoked    BOOLEAN DEFAULT FALSE
            )
        """)


def now():
    return int(time.time())


def hash_pw(salt, password):
    return hashlib.sha256((salt + password).encode("utf-8")).hexdigest()


def make_key():
    # SHADE-XXXX-XXXX-XXXX из безошибочного алфавита (без 0/O/1/I).
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    groups = ["".join(secrets.choice(alphabet) for _ in range(4)) for _ in range(3)]
    return "SHADE-" + "-".join(groups)


def is_admin(data):
    return data.get("admin_token", "") == ADMIN_TOKEN and ADMIN_TOKEN != "change-me-local-only"


@app.get("/")
def health():
    return jsonify(ok=True, service="shade-backend")


@app.post("/api/register")
def register():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    password = d.get("password") or ""
    if len(login) < 3:
        return jsonify(ok=False, error="Логин короче 3 символов")
    if len(password) < 4:
        return jsonify(ok=False, error="Пароль короче 4 символов")

    salt = secrets.token_hex(8)
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT 1 FROM users WHERE login=%s", (login,))
        if cur.fetchone():
            return jsonify(ok=False, error="Такой логин уже занят")
        cur.execute(
            "INSERT INTO users (login, salt, phash, created) VALUES (%s,%s,%s,%s)",
            (login, salt, hash_pw(salt, password), now()),
        )
    return jsonify(ok=True)


@app.post("/api/login")
def login():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    password = d.get("password") or ""
    hwid = d.get("hwid") or ""

    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT salt, phash, role, sub_expires, hwid FROM users WHERE login=%s", (login,))
        row = cur.fetchone()
        if not row or row[1] != hash_pw(row[0], password):
            return jsonify(ok=False, error="Неверный логин или пароль")
        salt, phash, role, sub_expires, saved_hwid = row

        # Привязка к железу: первый вход закрепляет HWID, дальше вход только с него.
        if saved_hwid and hwid and saved_hwid != hwid:
            return jsonify(ok=False, error="Аккаунт привязан к другому устройству")
        if not saved_hwid and hwid:
            cur.execute("UPDATE users SET hwid=%s WHERE login=%s", (hwid, login))

    active = sub_expires > now()
    return jsonify(ok=True, role=role, sub_expires=sub_expires,
                   active=active, sub_human=human(sub_expires))


@app.post("/api/activate")
def activate():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    key = (d.get("key") or "").strip().upper()

    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT sub_expires FROM users WHERE login=%s", (login,))
        u = cur.fetchone()
        if not u:
            return jsonify(ok=False, error="Аккаунт не найден")

        cur.execute("SELECT seconds, used_by, revoked FROM keys WHERE key=%s", (key,))
        k = cur.fetchone()
        if not k:
            return jsonify(ok=False, error="Ключ не существует")
        seconds, used_by, revoked = k
        if revoked:
            return jsonify(ok=False, error="Ключ отозван")
        if used_by:
            return jsonify(ok=False, error="Ключ уже активирован")

        # Продлеваем от большего из «сейчас» и текущего конца подписки —
        # активация второго ключа не сгорает, а суммируется.
        base = max(now(), u[0])
        new_expires = base + seconds
        cur.execute("UPDATE users SET sub_expires=%s WHERE login=%s", (new_expires, login))
        cur.execute("UPDATE keys SET used_by=%s, used_at=%s WHERE key=%s", (login, now(), key))

    return jsonify(ok=True, sub_expires=new_expires, sub_human=human(new_expires))


@app.post("/api/check")
def check():
    d = request.get_json(force=True, silent=True) or {}
    login = (d.get("login") or "").strip()
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT sub_expires FROM users WHERE login=%s", (login,))
        row = cur.fetchone()
    if not row:
        return jsonify(ok=False, error="Аккаунт не найден")
    return jsonify(ok=True, active=row[0] > now(), sub_expires=row[0], sub_human=human(row[0]))


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
    with db() as conn, conn.cursor() as cur:
        for _ in range(count):
            key = make_key()
            cur.execute(
                "INSERT INTO keys (key, seconds, created_at) VALUES (%s,%s,%s)",
                (key, DURATIONS[duration], now()),
            )
            created.append(key)
    return jsonify(ok=True, keys=created, duration=duration)


@app.post("/api/admin/keys")
def list_keys():
    d = request.get_json(force=True, silent=True) or {}
    if not is_admin(d):
        return jsonify(ok=False, error="Нет доступа")
    with db() as conn, conn.cursor() as cur:
        cur.execute("SELECT key, seconds, used_by, used_at, revoked FROM keys ORDER BY created_at DESC LIMIT 500")
        rows = cur.fetchall()
    keys = [dict(key=r[0], seconds=r[1], used_by=r[2], used_at=r[3], revoked=r[4]) for r in rows]
    return jsonify(ok=True, keys=keys)


@app.post("/api/admin/revoke")
def revoke():
    d = request.get_json(force=True, silent=True) or {}
    if not is_admin(d):
        return jsonify(ok=False, error="Нет доступа")
    key = (d.get("key") or "").strip().upper()
    with db() as conn, conn.cursor() as cur:
        cur.execute("UPDATE keys SET revoked=TRUE WHERE key=%s", (key,))
    return jsonify(ok=True)


def human(ts):
    if ts <= now():
        return "нет подписки"
    if ts - now() > 50 * 365 * 86400:
        return "навсегда"
    return datetime.fromtimestamp(ts, timezone.utc).strftime("%Y-%m-%d %H:%M UTC")


# Таблицы создаём при импорте модуля — gunicorn на Render просто импортирует app.
if DATABASE_URL:
    try:
        init_db()
    except Exception as e:  # noqa: BLE001 — на старте лучше залогировать и жить дальше
        print("init_db error:", e)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
