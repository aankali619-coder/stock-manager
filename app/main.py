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
    username: str; password: str; pin: str = ""

def strong_password(p):
    import re
    return (len(p) >= 8 and re.search(r"[A-Z]", p) and re.search(r"[a-z]", p)
            and re.search(r"\d", p) and re.search(r"[^A-Za-z0-9]", p))

import re
def valid_mpesa(v):
    v = v.strip().replace(" ", "")
    if re.fullmatch(r"(\+?254|0)?[17]\d{8}", v):  # Kenyan mobile e.g. 0712345678, +2547...
        return True
    if re.fullmatch(r"\d{5,7}", v):  # M-Pesa Till / Paybill shortcode
        return True
    return False

class ItemIn(BaseModel):
    sku: str = Field(..., min_length=1, max_length=64)
    name: str = Field(..., min_length=1, max_length=200)
    category: str = ""
    barcode: str = ""
    price: float = Field(..., ge=0)
    cost: float = Field(0, ge=0)
    quantity: int = Field(0, ge=0)
    min_stock: int = Field(0, ge=0)
    location: str = ""
    supplier: str = ""
    batch: str = ""
    expiry: str = ""

class AdjustIn(BaseModel):
    type: str = Field(..., pattern="^(in|out|adjust)$")
    qty: int = Field(..., gt=0)
    note: str = ""

class UserIn(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=6)
    role: str = Field("staff", pattern="^(admin|staff)$")
    locations: str = ""

def current_user(authorization: Optional[str] = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(401, "Not authenticated")
    token = authorization.split(" ", 1)[1]
    with conn() as c:
        u = c.execute("""SELECT u.id,u.username,u.role,u.locations FROM sessions s JOIN users u ON u.id=s.user_id
                         WHERE s.token=?""", (token,)).fetchone()
    if not u:
        raise HTTPException(401, "Invalid or expired token")
    return dict(u)

def allowed(u, location):
    if u["role"] == "admin" or not (u.get("locations") or "").strip():
        return True
    return location in [l.strip() for l in u["locations"].split(",")]

BOT = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT = os.environ.get("TELEGRAM_CHAT_ID", "")

def telegram(msg):
    if not (BOT and CHAT): return
    try:
        import requests
        requests.post(f"https://api.telegram.org/bot{BOT}/sendMessage",
                      json={"chat_id": CHAT, "text": msg}, timeout=5)
    except Exception: pass

def low_alert(item, c):
    if item["quantity"] <= item["min_stock"]:
        telegram(f"⚠️ LOW STOCK: {item['name']} ({item['sku']}) — {item['quantity']} left (min {item['min_stock']})")

def check_expiry(c):
    import datetime
    today = datetime.date.today().isoformat()
    for r in c.execute("SELECT name,sku,expiry FROM items WHERE expiry!='' AND expiry<=?", (today,)):
        telegram(f"⏰ EXPIRED/DUE: {r['name']} ({r['sku']}) expiry {r['expiry']}")

def require_admin(u=Depends(current_user)):
    if u["role"] != "admin":
        raise HTTPException(403, "Admin only")
    return u

@app.middleware("http")
async def nocache(request, call_next):
    r = await call_next(request)
    if request.method == "GET":
        r.headers["Cache-Control"] = "no-cache, must-revalidate"
    return r

@app.on_event("startup")
def startup(): init_db()

class GoogleIn(BaseModel):
    id_token: str

class Signup(BaseModel):
    username: str = Field(..., min_length=2, max_length=64)
    password: str = Field(..., min_length=6)
    email: str = ""
    phone: str = ""
    pin: str = ""
    confirm: str = ""
    mpesa: str = ""

@app.get("/api/config")
def config():
    return {"google_client_id": GOOGLE_CLIENT_ID}

@app.post("/api/signup")
def signup(b: Signup):
    if b.confirm and b.confirm != b.password:
        raise HTTPException(400, "Passwords do not match")
    if not strong_password(b.password):
        raise HTTPException(400, "Weak password: use 8+ chars with upper, lower, number and symbol")
    if b.pin and not (b.pin.isdigit() and len(b.pin) == 6):
        raise HTTPException(400, "Security PIN must be exactly 6 digits")
    if b.phone and not re.fullmatch(r"(\+?254|0)?[17]\d{8}", b.phone.strip().replace(" ", "")):
        raise HTTPException(400, "Invalid phone number: use Kenyan format e.g. 0712345678")
    if not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]{4,19}", b.username):
        raise HTTPException(400, "Weak username: 5-20 chars, start with a letter, only letters/numbers/underscore")
    if b.mpesa and not valid_mpesa(b.mpesa):
        raise HTTPException(400, "Invalid M-Pesa number: use a Kenyan phone (07XXXXXXXX) or a Till/Paybill shortcode (5-7 digits)")
    with conn() as c:
        try:
            c.execute("INSERT INTO users(username,password_hash,role,created_at,email,phone,pin_hash,mpesa) VALUES(?,?,?,?,?,?,?,?)",
                      (b.username, hash_password(b.password), "staff", now(), b.email, b.phone, hash_password(b.pin).decode() if b.pin else "", b.mpesa))
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
        return {"token": token, "username": row["username"], "role": row["role"], "seen_tutorial": row["seen_tutorial"] if "seen_tutorial" in row.keys() else 0}

@app.post("/api/login")
def login(b: Login):
    with conn() as c:
        row = c.execute("SELECT * FROM users WHERE username=?", (b.username,)).fetchone()
        if not row or not check_password(b.password, row["password_hash"]):
            raise HTTPException(401, "Bad credentials")
        stored_pin = row["pin_hash"] if "pin_hash" in row.keys() else ""
        if stored_pin:
            if not b.pin:
                raise HTTPException(401, "Security PIN required")
            import bcrypt as _b
            if not _b.checkpw(b.pin.encode(), stored_pin.encode() if isinstance(stored_pin, str) else stored_pin):
                raise HTTPException(401, "Wrong PIN")
        token = new_token()
        c.execute("INSERT INTO sessions(token,user_id,created_at) VALUES(?,?,?)", (token, row["id"], now()))
        return {"token": token, "username": row["username"], "role": row["role"], "seen_tutorial": row["seen_tutorial"] if "seen_tutorial" in row.keys() else 0}

@app.post("/api/tutorial-done")
def tutorial_done(u=Depends(current_user)):
    with conn() as c:
        c.execute("UPDATE users SET seen_tutorial=1 WHERE id=?", (u["id"],))
        return {"ok": True}

@app.post("/api/logout")
def logout(authorization: Optional[str] = Header(None)):
    if authorization:
        with conn() as c:
            c.execute("DELETE FROM sessions WHERE token=?", (authorization.split(" ")[-1],))
    return {"ok": True}

@app.get("/api/items")
def list_items(q: str = "", low: bool = False, location: str = "", u=Depends(current_user)):
    sql = "SELECT * FROM items WHERE 1=1"
    args = []
    if q:
        sql += " AND (name LIKE ? OR sku LIKE ? OR barcode LIKE ? OR category LIKE ? OR supplier LIKE ? OR batch LIKE ?)"
        like = f"%{q}%"; args += [like]*6
    if low:
        sql += " AND quantity <= min_stock"
    if location:
        sql += " AND location=?"; args.append(location)
    if u["role"] != "admin" and (u.get("locations") or "").strip():
        locs = [l.strip() for l in u["locations"].split(",")]
        sql += " AND location IN (" + ",".join("?"*len(locs)) + ")"; args += locs
    sql += " ORDER BY name"
    with conn() as c:
        return [dict(r) for r in c.execute(sql, args)]

@app.post("/api/items")
def add_item(b: ItemIn, u=Depends(current_user)):
    with conn() as c:
        try:
            cur = c.execute("""INSERT INTO items(sku,name,category,barcode,price,cost,quantity,min_stock,location,supplier,batch,expiry,created_at)
                               VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                            (b.sku, b.name, b.category, b.barcode, b.price, b.cost, b.quantity, b.min_stock, b.location, b.supplier, b.batch, b.expiry, now()))
        except Exception:
            raise HTTPException(409, "SKU already exists")
        if not allowed(u, b.location): raise HTTPException(403, "Not your location")
        if b.quantity > 0:
            c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                      (cur.lastrowid, u["id"], "in", b.quantity, "initial stock", now()))
        check_expiry(c)
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
        old = c.execute("SELECT price FROM items WHERE id=?", (item_id,)).fetchone()
        c.execute("""UPDATE items SET sku=?,name=?,category=?,barcode=?,price=?,cost=?,min_stock=?,location=?,supplier=?,batch=?,expiry=? WHERE id=?""",
                  (b.sku, b.name, b.category, b.barcode, b.price, b.cost, b.min_stock, b.location, b.supplier, b.batch, b.expiry, item_id))
        if old and old["price"] != b.price:
            c.execute("INSERT INTO price_history(item_id,old_price,new_price,changed_at) VALUES(?,?,?,?)",
                      (item_id, old["price"], b.price, now()))
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
        r = c.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
        if not allowed(u, r["location"]): raise HTTPException(403, "Not your location")
        if b.type == "out" and b.qty > r["quantity"]:
            raise HTTPException(400, "Not enough stock")
        delta = b.qty if b.type == "in" else (-b.qty if b.type == "out" else b.qty - r["quantity"])
        c.execute("UPDATE items SET quantity = quantity + ? WHERE id=?", (delta, item_id))
        c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                  (item_id, u["id"], b.type, delta, b.note, now()))
        r2 = c.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        low_alert(r2, c)
        check_expiry(c)
        return {"quantity": r2["quantity"]}

class PoItem(BaseModel):
    item_id: int; qty: int = Field(..., gt=0); price: float = 0
class PoIn(BaseModel):
    supplier_id: int; items: list[PoItem]
class SaleItem(BaseModel):
    item_id: int; qty: int = Field(..., gt=0); price: float = -1
class SaleIn(BaseModel):
    customer: str = ""; items: list[SaleItem]; mpesa: str = ""
class SupplierIn(BaseModel):
    name: str = Field(..., min_length=1); contact: str = ""

@app.get("/api/suppliers")
def suppliers(u=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM suppliers ORDER BY name")]

@app.post("/api/suppliers")
def add_supplier(b: SupplierIn, u=Depends(current_user)):
    with conn() as c:
        cur = c.execute("INSERT INTO suppliers(name,contact,created_at) VALUES(?,?,?)", (b.name, b.contact, now()))
        return {"id": cur.lastrowid}

@app.delete("/api/suppliers/{sid}")
def del_supplier(sid: int, u=Depends(require_admin)):
    with conn() as c:
        c.execute("DELETE FROM suppliers WHERE id=?", (sid,)); return {"ok": True}

@app.get("/api/pos")
def pos(u=Depends(current_user)):
    with conn() as c:
        rows=[dict(r) for r in c.execute("SELECT p.*,s.name supplier FROM purchase_orders p JOIN suppliers s ON s.id=p.supplier_id ORDER BY p.id DESC")]
        for r in rows:
            r["items"]=[dict(t) for t in c.execute("SELECT pi.*,i.name,i.sku FROM po_items pi JOIN items i ON i.id=pi.item_id WHERE pi.po_id=?",(r["id"],))]
        return rows

@app.post("/api/pos")
def add_po(b: PoIn, u=Depends(current_user)):
    with conn() as c:
        cur = c.execute("INSERT INTO purchase_orders(supplier_id,status,created_at) VALUES(?,?,?)", (b.supplier_id, "pending", now()))
        for it in b.items:
            c.execute("INSERT INTO po_items(po_id,item_id,qty,price) VALUES(?,?,?,?)", (cur.lastrowid, it.item_id, it.qty, it.price))
        return {"id": cur.lastrowid}

@app.post("/api/pos/{pid}/receive")
def receive(pid: int, u=Depends(current_user)):
    with conn() as c:
        po = c.execute("SELECT * FROM purchase_orders WHERE id=?", (pid,)).fetchone()
        if not po: raise HTTPException(404, "Not found")
        if po["status"] == "received": raise HTTPException(400, "Already received")
        for it in c.execute("SELECT * FROM po_items WHERE po_id=?", (pid,)):
            c.execute("UPDATE items SET quantity=quantity+?, cost=? WHERE id=?", (it["qty"], it["price"] or 0, it["item_id"]))
            c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                      (it["item_id"], u["id"], "in", it["qty"], f"PO #{pid}", now()))
        c.execute("UPDATE purchase_orders SET status='received' WHERE id=?", (pid,))
        return {"ok": True}

@app.get("/api/sales")
def sales_list(u=Depends(current_user)):
    with conn() as c:
        rows=[dict(r) for r in c.execute("SELECT * FROM sales ORDER BY id DESC")]
        for r in rows:
            r["items"]=[dict(t) for t in c.execute("SELECT si.*,i.name,i.sku FROM sale_items si JOIN items i ON i.id=si.item_id WHERE si.sale_id=?",(r["id"],))]
        return rows

@app.post("/api/sales")
def add_sale(b: SaleIn, u=Depends(current_user)):
    with conn() as c:
        for it in b.items:
            r = c.execute("SELECT * FROM items WHERE id=?", (it.item_id,)).fetchone()
            if not r: raise HTTPException(404, f"Item {it.item_id} not found")
            if it.qty > r["quantity"]: raise HTTPException(400, f"Not enough stock for {r['name']}")
            unit = it.price if it.price and it.price >= 0 else r["price"]
            total += it.qty * unit
        cur = c.execute("INSERT INTO sales(customer,total,created_at,mpesa) VALUES(?,?,?,?)", (b.customer, round(total,2), now(), b.mpesa))
        for it in b.items:
            r = c.execute("SELECT price FROM items WHERE id=?", (it.item_id,)).fetchone()
            unit = it.price if it.price and it.price >= 0 else r["price"]
            c.execute("INSERT INTO sale_items(sale_id,item_id,qty,price) VALUES(?,?,?,?)", (cur.lastrowid, it.item_id, it.qty, unit))
            c.execute("UPDATE items SET quantity=quantity-? WHERE id=?", (it.qty, it.item_id))
            c.execute("INSERT INTO transactions(item_id,user_id,type,qty_change,note,created_at) VALUES(?,?,?,?,?,?)",
                      (it.item_id, u["id"], "out", -it.qty, f"Sale #{cur.lastrowid}", now()))
        stk = stk_push(b.mpesa, total, cur.lastrowid) if b.mpesa else None
        return {"id": cur.lastrowid, "total": round(total,2), "stk": stk}

class PriceIn(BaseModel):
    price: float = Field(..., ge=0)
    cost: float = Field(0, ge=0)

def stk_push(phone, amount, ref):
    import os, base64, datetime, requests
    key, secret, shortcode, passkey = (os.environ.get(v, "") for v in ("DARAJA_CONSUMER_KEY","DARAJA_CONSUMER_SECRET","DARAJA_SHORTCODE","DARAJA_PASSKEY"))
    if not all([key, secret, shortcode, passkey]):
        return {"mode": "manual", "message": f"Ask customer to pay KSh {amount} to M-Pesa {phone} (STK push API not configured)."}
    try:
        t = requests.get("https://sandbox.safaricom.co.ke/oauth/v1/generate?grant_type=client_credentials", auth=(key, secret), timeout=10).json()["access_token"]
        ts = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
        pwd = base64.b64encode(f"{shortcode}{passkey}{ts}".encode()).decode()
        msisdn = phone.strip().replace("+", "").replace(" ", "")
        if msisdn.startswith("0"): msisdn = "254" + msisdn[1:]
        r = requests.post("https://sandbox.safaricom.co.ke/mpesa/stkpush/v1/processrequest",
            headers={"Authorization": f"Bearer {t}"}, json={
                "BusinessShortCode": shortcode, "Password": pwd, "Timestamp": ts,
                "TransactionType": "CustomerPayBillOnline", "Amount": int(amount),
                "PartyA": msisdn, "PartyB": shortcode, "PhoneNumber": msisdn,
                "CallBackURL": os.environ.get("DARAJA_CALLBACK", "https://example.com/cb"),
                "AccountReference": f"Sale{ref}", "TransactionDesc": f"Sale {ref}"}, timeout=15)
        return {"mode": "stk", "message": r.json().get("CustomerMessage", "STK push sent — check your phone.")}
    except Exception as e:
        return {"mode": "error", "message": str(e)}

from fastapi import Request
@app.post("/api/mpesa-callback")
async def mpesa_callback(request: Request):
    try:
        data = await request.json()
        print("MPESA CALLBACK:", data)
    except Exception:
        pass
    return {"ResultCode": 0, "ResultDesc": "Accepted"}

@app.get("/api/missing")
def missing(u=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM items WHERE quantity = 0 ORDER BY name")]

@app.get("/api/prices")
def prices(u=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT id,sku,name,category,price,cost,quantity,location FROM items ORDER BY name")]

@app.post("/api/items/{item_id}/price")
def set_price(item_id: int, b: PriceIn, u=Depends(current_user)):
    with conn() as c:
        r = c.execute("SELECT price FROM items WHERE id=?", (item_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
        c.execute("UPDATE items SET price=?, cost=? WHERE id=?", (b.price, b.cost, item_id))
        c.execute("INSERT INTO price_history(item_id,old_price,new_price,changed_at) VALUES(?,?,?,?)",
                  (item_id, r["price"], b.price, now()))
        return {"ok": True}

@app.get("/api/price-history")
def price_history(item_id: int = 0, u=Depends(current_user)):
    with conn() as c:
        if item_id:
            rows = c.execute("SELECT ph.*,i.name,i.sku FROM price_history ph JOIN items i ON i.id=ph.item_id WHERE ph.item_id=? ORDER BY ph.id DESC", (item_id,))
        else:
            rows = c.execute("SELECT ph.*,i.name,i.sku FROM price_history ph JOIN items i ON i.id=ph.item_id ORDER BY ph.id DESC LIMIT 100")
        return [dict(r) for r in rows]

@app.get("/api/transactions")
def txs(limit: int = 100, u=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute("""SELECT t.id,t.type,t.qty_change,t.note,t.created_at,i.name item,i.sku,u.username
            FROM transactions t JOIN items i ON i.id=t.item_id JOIN users u ON u.id=t.user_id
            ORDER BY t.id DESC LIMIT ?""", (limit,))]

@app.get("/api/expiring")
def expiring(days: int = 30, u=Depends(current_user)):
    import datetime
    d = (datetime.date.today()+datetime.timedelta(days=days)).isoformat()
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT * FROM items WHERE expiry!='' AND expiry<=? ORDER BY expiry", (d,))]

@app.get("/api/warehouses")
def warehouses(u=Depends(current_user)):
    with conn() as c:
        return [dict(r) for r in c.execute("""SELECT COALESCE(NULLIF(location,''),'(unassigned)') location,
            COUNT(*) items, COALESCE(SUM(quantity),0) units, COALESCE(SUM(quantity*price),0) value
            FROM items GROUP BY location ORDER BY value DESC""")]

@app.get("/api/charts")
def charts(u=Depends(current_user)):
    with conn() as c:
        cats = [dict(r) for r in c.execute("SELECT category, SUM(quantity*price) value FROM items GROUP BY category ORDER BY value DESC")]
        return {"by_category": cats}

@app.get("/api/locations")
def locations(u=Depends(current_user)):
    with conn() as c:
        return [r["location"] for r in c.execute("SELECT DISTINCT location FROM items WHERE location!='' ORDER BY location")]

@app.get("/api/items/export.csv")
def export_csv(u=Depends(current_user)):
    import io, csv
    with conn() as c:
        rows = list(c.execute("SELECT sku,name,category,barcode,price,cost,quantity,min_stock,location,supplier,batch,expiry FROM items ORDER BY name"))
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["sku","name","category","barcode","price","cost","quantity","min_stock","location","supplier","batch","expiry"])
    for r in rows: w.writerow([r[k] for k in r.keys()])
    from fastapi.responses import Response
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition":"attachment; filename=items.csv"})

@app.get("/label/{item_id}")
def label(item_id: int):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE id=?", (item_id,)).fetchone()
        if not r: raise HTTPException(404, "Not found")
    html = f"""<!doctype html><html><head><script src="https://cdn.jsdelivr.net/npm/jsbarcode@3.11.6/dist/JsBarcode.all.min.js"></script>
    <body style="font-family:Arial;text-align:center;padding:20px"><h3>{r['name']}</h3><svg id="b"></svg><p>KSh {r['price']:.2f} — {r['location']}</p><script>JsBarcode("#b","{r['barcode'] or r['sku']}",{{format:"CODE128"}})</script></body></html>"""
    from fastapi.responses import HTMLResponse
    return HTMLResponse(html)

@app.get("/api/barcode/{code}")
def by_barcode(code: str, u=Depends(current_user)):
    with conn() as c:
        r = c.execute("SELECT * FROM items WHERE barcode=? OR sku=?", (code, code)).fetchone()
        if not r: raise HTTPException(404, "Item not found")
        return dict(r)

@app.get("/api/stats")
def stats(u=Depends(current_user)):
    with conn() as c:
        items = c.execute("SELECT COUNT(*) n, COALESCE(SUM(quantity),0) total, COALESCE(SUM(quantity*price),0) value, COALESCE(SUM(quantity*cost),0) cost_value FROM items").fetchone()
        low = c.execute("SELECT COUNT(*) n FROM items WHERE quantity<=min_stock").fetchone()
        return {"items": items["n"], "units": items["total"], "value": round(items["value"], 2), "cost_value": round(items["cost_value"],2), "profit": round(items["value"]-items["cost_value"],2), "low_stock": low["n"]}

@app.post("/api/users")
def add_user(b: UserIn, u=Depends(require_admin)):
    with conn() as c:
        try:
            c.execute("INSERT INTO users(username,password_hash,role,created_at,locations) VALUES(?,?,?,?,?)",
                      (b.username, hash_password(b.password), b.role, now(), b.locations))
        except Exception:
            raise HTTPException(409, "Username taken")
        return {"ok": True}

@app.get("/api/users")
def list_users(u=Depends(require_admin)):
    with conn() as c:
        return [dict(r) for r in c.execute("SELECT id,username,role,locations,created_at FROM users ORDER BY id")]

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

@app.get("/copyright")
def copyright(): return FileResponse(os.path.join(BASE, "static", "copyright.html"))

@app.get("/items-page")
def items_page(): return FileResponse(os.path.join(BASE, "static", "items.html"))

@app.get("/movements")
def movements(): return FileResponse(os.path.join(BASE, "static", "movements.html"))

@app.get("/warehouses")
def warehouses_page(): return FileResponse(os.path.join(BASE, "static", "warehouses.html"))

@app.get("/alerts")
def alerts(): return FileResponse(os.path.join(BASE, "static", "alerts.html"))

@app.get("/reports")
def reports(): return FileResponse(os.path.join(BASE, "static", "reports.html"))

@app.get("/users-page")
def users_page(): return FileResponse(os.path.join(BASE, "static", "users.html"))

@app.get("/suppliers")
def suppliers_page(): return FileResponse(os.path.join(BASE, "static", "suppliers.html"))

@app.get("/purchases")
def purchases_page(): return FileResponse(os.path.join(BASE, "static", "purchases.html"))

@app.get("/sales-page")
def sales_page(): return FileResponse(os.path.join(BASE, "static", "sales.html"))

@app.get("/prices")
def prices_page(): return FileResponse(os.path.join(BASE, "static", "prices.html"))

@app.get("/pos")
def pos(): return FileResponse(os.path.join(BASE, "static", "pos.html"))

@app.get("/subscription")
def subscription(u=Depends(current_user)):
    with conn() as c:
        try:
            u = c.execute("SELECT subscription FROM users WHERE username=?", (u["username"],)).fetchone()
            subscription_val = u[0] if u else "free"
        except Exception:
            subscription_val = "free"
        return {"subscription": subscription_val}

@app.get("/subscription")
def subscription(u=Depends(current_user)):
    with conn() as c:
        try:
            u = c.execute("SELECT subscription FROM users WHERE username=?", (u["username"],)).fetchone()
            subscription_val = u[0] if u else "free"
        except Exception:
            subscription_val = "free"
        return {"subscription": subscription_val}

@app.get("/login")
def login_page(): return FileResponse(os.path.join(BASE, "static", "login.html"))

@app.get("/manifest.json")
def manifest(): return FileResponse(os.path.join(BASE, "static", "manifest.json"), media_type="application/manifest+json")

@app.get("/sw.js")
def sw():
    from fastapi.responses import FileResponse as FR
    r = FR(os.path.join(BASE, "static", "sw.js"), media_type="application/javascript")
    r.headers["Service-Worker-Allowed"] = "/"
    r.headers["Cache-Control"] = "no-cache"
    return r
