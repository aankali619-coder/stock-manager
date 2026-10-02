import os, sys
sys.path.insert(0, os.path.dirname(__file__))
from fastapi import FastAPI, Depends, HTTPException, Header
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field
from typing import Optional
from db import conn, init_db, hash_password, check_password, new_token, now
import os, secrets as _s
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "")

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
app = FastAPI(title="Stock Manager")

class Login(BaseModel):
    username: str; password: str

class ItemIn(BaseModel):
    sku: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=200)
    category: str = ""
    barcode: str = ""
    price: float = Field(..., ge=0)
    quantity: int = Field(0, ge=0)
    min_stock: int = Field(0, ge=0)
    location: str = ""

class AdjustIn(BaseModel):
    type: str = Field(..., pattern="^(in|out|adjust)$")
    qty: int = Field(..., gt=0)
    note: str = ""

class UserIn(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=6)
    role: str = Field("staff", pattern="^(admin|staff)$")

def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = authorization.split(" ", 1)[1]
    with conn() as c:
        u = c.execute("""SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id
                         WHERE s.token=?""", (token,)).fetchone()
    if not u:
        raise HTTPException(401, "Invalid or expired token")
    return dict(u)

def require_admin(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return u

@app.on_event("startup")
def startup(): init_db()

class GoogleIn(BaseModel):
    id_token: str

class Signup(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=6)
    email: str = ""

@app.get("/api/config")
def config():
    return {"google_client_id": GOOGLE_CLIENT_ID}

@app.post("/api/signup")
def signup(b: Signup):
    with conn() as c:
        try:
            c.execute("INSERT INTO users(username,password_hash,role,created_at,email) VALUES(?,?,?,?,?)",
                      (b.username, hash_password(b.password), "staff", now(), b.email))
        except Exception:
            raise HTTPException(409, "Username already taken")
        return {"ok": True}

@app.post("/api/google")
def google_login(b: GoogleIn):
    if not GOOGLE_CLIENT_ID:
        raise HTTPException(500, "Google sign-in not configured")
    try:
        from google.oauth2 import id_token as g_id_token
        from google.auth.transport import requests as g_requests
        info = g_id_token.verify_oauth2_token(b.id_token, g_requests.Request(), GOOGLE_CLIENT_ID)
    except Exception:
        raise HTTPException(401, "Invalid Google token")
    email = info.get("email", "")
    name = info.get("name") or email.split("@")[0]
    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        if not row:
            try:
                c.execute("INSERT INTO users(username,password_hash,role,created_at,email) VALUES(?,?,?,?,?)",
                          (email.split('@')[0] + _s.token_hex(3), hash_password(_s.token_hex(16)), "staff", now(), email))
            except Exception:
                raise HTTPException(409, "Username conflict, try again")
            row = c.execute("SELECT * FROM users WHERE email=?", (email,)).fetchone()
        token = new_token()
        c.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)", (token, row["id"], now()))
        return {"token": token, "username": row["username"], "role": row["role"]}

@app.post("/api/login")
def login(b: Login):
    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (b.username,)).fetchone()
        if not row or not check_password(b.password, row["password_hash"]):
            raise HTTPException(401, "Bad credentials")
        token = new_token()
        c.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)", (token, row["id"], now()))
        return {"token": token, "username": row["username"], "role": row["role"]}

@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization:
        with conn() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (authorization.split(" ")[-1],))
    return {"ok": True}

@app.get("/api/items")
def list_items(q: str = "", low: bool = False, u=Depends(current_user)):
    sql = "SELECT * FROM items WHERE 1=1"
    args = []
    if q:
        sql += " AND (name LIKE ? OR sku LIKE ? OR barcode LIKE ? OR category LIKE ?)"
        like = f"%{q}%"; args += [like]*4
    if low:
        sql += " AND quantity <= min_stock"
    sql += " ORDER BY name"
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]

@app.post("/api/items")
def add_item(b: ItemIn, u=Depends(current_user)):
    with conn() as c:
        try:
            cur = c.execute("""INSERT INTO items(sku,name,category,barcode,price,quantity,min_stock,location,created_at)
                               VALUES(?,?,?,?,?,?,?,?,?)""",
                            (b.sku, b.name, b.category, b.barcode, b.price, b.quantity, b.min_stock, b.location, now()))
        except Exception:
            raise HTTPException(409, "SKU already exists")
        if b.quantity > 0:
            c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                      (cur.lastrowid, u["id"], "in", b.quantity, "initial stock", now()))
        return {"id": cur.lastrowid}

@app.get("/api/items/{item_id}")
def get_item(item_id: int, u=Depends(current_user)):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
        txs = [dict(t) for t in c.execute(
            "SELECT t.*,u.username FROM transactions t JOIN users u ON u.id=t.user_id WHERE item_id=? ORDER BY t.id DESC LIMIT 50", (item_id,))]
        return {"item": dict(r), "transactions": txs}

@app.put("/api/items/{item_id}")
def update_item(item_id: int, b: ItemIn, u=Depends(current_user)):
    with conn() as c:
        if not c.execute("SELECT id FROM items WHERE id=?", (item_id,)).fetchone():
            raise HTTPException(404, "Not found")
        c.execute("""UPDATE items SET sku=?,name=?,category=?,barcode=?,price=?,min_stock=?,location=? WHERE id=?""",
                  (b.sku, b.name, b.category, b.barcode, b.price, b.min_stock, b.location, item_id))
        return {"ok": True}

@app.delete("/api/items/{item_id}")
def delete_item(item_id: int, u=Depends(require_admin)):
    with conn() as c:
        c.execute("DELETE FROM transactions WHERE item_id=?", (item_id,))
        c.execute("DELETE FROM items WHERE id=?", (item_id,))
        return {"ok": True}

@app.post("/api/items/{item_id}/adjust")
def adjust(item_id: int, b: AdjustIn, u=Depends(current_user)):
    with conn() as c:
        r = c.execute("SELECT quantity FROM items WHERE id=?", (item_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
        if b.type == "out" and b.qty > r["quantity"]:
            raise HTTPException(400, "Not enough stock")
        delta = b.qty if b.type == "in" else (-b.qty if b.type == "out" else b.qty - r["quantity"])
        c.execute("UPDATE items SET quantity = quantity + ? WHERE id=?", (delta, item_id))
        c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                  (item_id, u["id"], b.type, delta, b.note, now()))
        return {"quantity": c.execute("SELECT quantity FROM items WHERE id=?", (item_id,)).fetchone()["quantity"]}

@app.get("/api/barcode/{code}")
def by_barcode(code: str, u=Depends(current_user)):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE barcode=? OR sku=?", (code, code)).fetchone()
        if not r: raise HTTPException(404, "Item not found")
        return dict(r)

@app.get("/api/stats")
def stats(u=Depends(current_user)):
    with conn() as c:
        items = c.execute("SELECT COUNT(*) n, COALESCE(SUM(quantity),0) total, COALESCE(SUM(quantity*price),0) value FROM items").fetchone()
        low = c.execute("SELECT COUNT(*) n FROM items WHERE quantity<=min_stock").fetchone()
        return {"items": items["n"], "units": items["total"], "value": round(items["value"], 2), "low_stock": low["n"]}

@app.post("/api/users")
def add_user(b: UserIn, u=Depends(require_admin)):
    with conn() as c:
        try:
            c.execute("INSERT INTO users(username,password_hash,role,created_at) VALUES(?,?,?,?)",
                      (b.username, hash_password(b.password), b.role, now()))
        except Exception:
            raise HTTPException(409, "Username taken")
        return {"ok": True}

@app.get("/api/users")
def list_users(u=Depends(require_admin)):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT id,username,role,created_at FROM users ORDER BY id")]

@app.delete("/api/users/{uid}")
def del_user(uid: int, u=Depends(require_admin)):
    if uid == u["id"]: raise HTTPException(400, "Can't delete yourself")
    with conn() as c:
        c.execute("DELETE FROM sessions WHERE user_id=?", (uid,))
        c.execute("DELETE FROM users WHERE id=?", (uid,))
        return {"ok": True}

app.mount("/static", StaticFiles(directory=os.path.join(BASE, "static")), name="static")

@app.get("/")
def index():
    return FileResponse(os.path.join(BASE, "static", "index.html"))

@app.get("/about")
def about(): return FileResponse(os.path.join(BASE, "pages", "about.html"))

@app.get("/features")
def features(): return FileResponse(os.path.join(BASE, "pages", "features.html"))

@app.get("/help")
def help_(): return FileResponse(os.path.join(BASE, "pages", "help.html"))
