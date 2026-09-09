# shade-backend

Сервер ключей Shade. Разворачивается на Render по `render.yaml` (web + Postgres).

## Локально
    pip install -r requirements.txt
    set DATABASE_URL=postgresql://...   # или локальный postgres
    set ADMIN_TOKEN=любой-секрет
    python app.py

## Эндпоинты
- `POST /api/register` `{login, password}`
- `POST /api/login` `{login, password, hwid}`
- `POST /api/activate` `{login, key, hwid}`
- `POST /api/check` `{login, hwid}`
- `POST /api/admin/genkey` `{admin_token, duration, count}` — duration: 1h|7d|30d|90d|180d|forever
- `POST /api/admin/keys` `{admin_token}`
- `POST /api/admin/revoke` `{admin_token, key}`
