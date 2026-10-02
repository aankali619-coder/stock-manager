# Stock Manager — Design

## Goals
Track items (details, price, quantity), manage stock in/out, run on desktop + mobile, secure against unauthorized access, fast and simple.

## Architecture
- **Backend**: FastAPI (Python) — fast, typed, auto docs at `/docs`
- **DB**: SQLite (single file, zero setup, ACID, fine for small/medium stock)
- **Auth**: session tokens (Bearer), bcrypt password hashing, roles: `admin` / `staff`
- **Frontend**: one mobile-friendly HTML page served by the same app (works in any browser, phone or PC). Camera barcode scanning via html5-qrcode.

## Data model
- `users(id, username, password_hash, role, created_at)`
- `items(id, sku, name, category, barcode, price, quantity, min_stock, location, created_at)`
- `transactions(id, item_id, user_id, type[in|out|adjust], qty_change, note, created_at)` — full audit trail of who changed stock and when
- `sessions(token, user_id, created_at)`

## API
| Method | Path | Description |
|---|---|---|
| POST | /api/login | get token |
| GET/POST | /api/items | list / add |
| GET/PUT/DELETE | /api/items/{id} | view / edit / delete (delete=admin) |
| POST | /api/items/{id}/adjust | stock in/out/set |
| GET | /api/barcode/{code} | lookup by barcode/SKU |
| GET | /api/stats | totals, low-stock count |
| GET/POST/DELETE | /api/users | user management (admin) |

## Security
- Passwords bcrypt-hashed; all endpoints except login require a token
- Role-based access (only admins delete items/manage users)
- Check constraints keep price/quantity ≥ 0; stock-out can't go negative
- No CORS opened — only served to clients that ask for it

## Run
```bash
cd stock-manager/app
python3 -m uvicorn main:app --host 0.0.0.0 --port 8000
```
Open http://<your-computer-ip>:8000 on phone/desktop.
Default login: **admin / admin123** (change after first login by creating a new admin and removing the default).

## Extend later
- PostgreSQL for multi-machine/concurrent use
- HTTPS via nginx or Caddy if exposed beyond LAN
- Low-stock email/Telegram alerts, export CSV, multi-warehouse
