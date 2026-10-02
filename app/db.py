import sqlite3, os, secrets, datetime
import bcrypt

DATABASE_URL = os.environ.get("DATABASE_URL")
DATA_DIR = "/tmp" if os.environ.get("VERCEL") else os.path.join(os.path.dirname(__file__), "..")
DB_PATH = os.environ.get("STOCK_DB", os.path.join(DATA_DIR, "stock.db"))
IS_PG = bool(DATABASE_URL)

class PgCursor:
    def __init__(self, cur, ret=None): self._cur = cur; self._ret = ret
    def fetchone(self): return self._cur.fetchone()
    def fetchall(self): return self._cur.fetchall()
    @property
    def lastrowid(self):
        if self._ret is not None: return self._ret.get("id")
        try: return self._cur.fetchone()["id"]
        except Exception: return None

class PgConn:
    def __init__(self, c): self._c = c
    def execute(self, sql, args=()):
        returning = sql.lstrip().upper().startswith("INSERT") and "RETURNING" not in sql.upper() and any(f"INTO {t}" in sql for t in ("items","users","transactions","suppliers","purchase_orders","po_items","sales","sale_items"))
        if returning:
            sql = sql.rstrip().rstrip(";") + " RETURNING id"
        cur = self._c.execute(sql.replace("?", "%s"), args)
        return PgCursor(cur, cur.fetchone() if returning else None)
    def executescript(self, s):
        for stmt in s.split(";"):
            if stmt.strip(): self._c.execute(stmt)
    def __enter__(self): return self
    def __exit__(self, *a): self._c.commit(); self._c.close()

def conn():
    if IS_PG:
        import psycopg
        from psycopg.rows import dict_row
        return PgConn(psycopg.connect(DATABASE_URL, row_factory=dict_row, autocommit=True))
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    pk = "id SERIAL PRIMARY KEY" if IS_PG else "id INTEGER PRIMARY KEY"
    with conn() as c:
        c.executescript(f"""
        CREATE TABLE IF NOT EXISTS users(
            {pk}, username TEXT UNIQUE NOT NULL, password_hash BYTEA NOT NULL,
            role TEXT NOT NULL CHECK(role IN ('admin','staff')), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS items(
            {pk}, sku TEXT UNIQUE NOT NULL, name TEXT NOT NULL, category TEXT DEFAULT '',
            barcode TEXT DEFAULT '', price REAL NOT NULL CHECK(price >= 0),
            quantity INTEGER NOT NULL DEFAULT 0 CHECK(quantity >= 0),
            min_stock INTEGER NOT NULL DEFAULT 0, location TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS transactions(
            {pk}, item_id INTEGER NOT NULL REFERENCES items(id),
            user_id INTEGER NOT NULL REFERENCES users(id),
            type TEXT NOT NULL CHECK(type IN ('in','out','adjust')),
            qty_change INTEGER NOT NULL, note TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(
            token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS suppliers(
            {pk}, name TEXT NOT NULL, contact TEXT DEFAULT '', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS purchase_orders(
            {pk}, supplier_id INTEGER NOT NULL REFERENCES suppliers(id), status TEXT NOT NULL DEFAULT 'pending', created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS po_items(
            {pk}, po_id INTEGER NOT NULL REFERENCES purchase_orders(id), item_id INTEGER NOT NULL REFERENCES items(id), qty INTEGER NOT NULL, price REAL NOT NULL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS sales(
            {pk}, customer TEXT DEFAULT '', total REAL NOT NULL DEFAULT 0, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sale_items(
            {pk}, sale_id INTEGER NOT NULL REFERENCES sales(id), item_id INTEGER NOT NULL REFERENCES items(id), qty INTEGER NOT NULL, price REAL NOT NULL);
        """)
        try:
            c.execute("ALTER TABLE users ADD COLUMN email TEXT")
        except Exception:
            pass
        try:
            c.execute("ALTER TABLE users ADD COLUMN locations TEXT DEFAULT ''")
        except Exception:
            pass
        for col, ddl in [("cost", "ALTER TABLE items ADD COLUMN cost REAL DEFAULT 0"),
                         ("supplier", "ALTER TABLE items ADD COLUMN supplier TEXT DEFAULT ''"),
                         ("batch", "ALTER TABLE items ADD COLUMN batch TEXT DEFAULT ''"),
                         ("expiry", "ALTER TABLE items ADD COLUMN expiry TEXT DEFAULT ''")]:
            try: c.execute(ddl)
            except Exception: pass
        row = c.execute("SELECT id FROM users WHERE username='admin'").fetchone()
        if not row:
            ph = bcrypt.hashpw(b"admin123", bcrypt.gensalt())
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                      ("admin", ph, "admin", now()))

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")

def hash_password(pw: str) -> bytes:
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

def check_password(pw: str, h) -> bool:
    if not isinstance(h, (bytes, bytearray, memoryview)):
        h = bytes(h)
    return bcrypt.checkpw(pw.encode(), bytes(h))

def new_token() -> str:
    return secrets.token_hex(24)
