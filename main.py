import csv, io, os, datetime as dt
from calendar import monthrange
from typing import Literal, Optional
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text
import hmac, hashlib, base64, time, secrets
from fastapi import FastAPI, HTTPException, Depends, Request

# DATABASE_URL = PostgreSQL connection string (Render / Neon / Supabase).
# If it is not set, a local SQLite file is used so you can still develop offline.
url = os.getenv("DATABASE_URL", "sqlite:///tracker.db")
if url.startswith("postgres://"):
    url = url.replace("postgres://", "postgresql+psycopg2://", 1)
elif url.startswith("postgresql://"):
    url = url.replace("postgresql://", "postgresql+psycopg2://", 1)

engine = create_engine(url, pool_pre_ping=True)
IS_PG = engine.dialect.name == "postgresql"

# ---------- single-user login (credentials come from environment variables) ----------
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "").strip().lower()
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
SECRET_KEY = os.getenv("SECRET_KEY", "")
if not (ADMIN_EMAIL and ADMIN_PASSWORD and SECRET_KEY):
    raise RuntimeError("Set ADMIN_EMAIL, ADMIN_PASSWORD and SECRET_KEY environment variables")
TOKEN_DAYS = 7


def _b64(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")


def _sign(body: str) -> str:
    return _b64(hmac.new(SECRET_KEY.encode(), body.encode(), hashlib.sha256).digest())


def make_token() -> str:
    body = _b64(str(int(time.time()) + TOKEN_DAYS * 86400).encode())
    return f"{body}.{_sign(body)}"


def verify_token(tok: str) -> bool:
    try:
        body, sig = tok.split(".", 1)
        if not hmac.compare_digest(sig, _sign(body)):
            return False
        exp = int(base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode())
        return exp > time.time()
    except Exception:
        return False


def require_auth(request: Request):
    if request.method == "OPTIONS" or request.url.path == "/api/login":
        return
    h = request.headers.get("authorization", "")
    if not h.startswith("Bearer ") or not verify_token(h[7:]):
        raise HTTPException(401, "Unauthorized")


# Every route is protected by default; API docs are switched off so nothing leaks.
app = FastAPI(title="Money Tracker", dependencies=[Depends(require_auth)],
              docs_url=None, redoc_url=None, openapi_url=None)

_fails = {}  # ip -> (count, locked_until)


class LoginIn(BaseModel):
    email: str
    password: str


@app.post("/api/login")
def login(d: LoginIn, request: Request):
    ip = (request.headers.get("x-forwarded-for", "").split(",")[0].strip()
          or (request.client.host if request.client else "?"))
    count, until = _fails.get(ip, (0, 0))
    if until > time.time():
        raise HTTPException(429, "Too many attempts. Try again in a few minutes.")
    ok_email = hmac.compare_digest(d.email.strip().lower().encode(), ADMIN_EMAIL.encode())
    ok_pw = hmac.compare_digest(d.password.encode(), ADMIN_PASSWORD.encode())
    if not (ok_email and ok_pw):
        count += 1
        _fails[ip] = (count, time.time() + 300 if count >= 5 else 0)
        time.sleep(1)  # slows down guessing
        raise HTTPException(401, "Wrong email or password")
    _fails.pop(ip, None)
    return {"token": make_token()}
origins = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",")]
app.add_middleware(CORSMiddleware, allow_origins=origins, allow_methods=["*"], allow_headers=["*"])


def q(sql, args=(), one=False, write=False):
    parts = sql.split("?")  # keep "?" placeholders in the SQL below, convert to named params
    sql2 = parts[0] + "".join(f":p{i}{p}" for i, p in enumerate(parts[1:]))
    params = {f"p{i}": v for i, v in enumerate(args)}
    with engine.begin() as c:
        if write:
            if sql2.lstrip().upper().startswith("INSERT"):
                if IS_PG:
                    return c.execute(text(sql2 + " RETURNING id"), params).scalar()
                return c.execute(text(sql2), params).lastrowid
            c.execute(text(sql2), params)
            return None
        rows = [dict(r) for r in c.execute(text(sql2), params).mappings().all()]
        return (rows[0] if rows else None) if one else rows


PK = "SERIAL PRIMARY KEY" if IS_PG else "INTEGER PRIMARY KEY"
q(f"""CREATE TABLE IF NOT EXISTS transactions(
  id {PK}, type TEXT, amount FLOAT, category TEXT, note TEXT, date TEXT)""", write=True)
q(f"""CREATE TABLE IF NOT EXISTS loans(
  id {PK}, person TEXT, direction TEXT, amount FLOAT, due_date TEXT, note TEXT, created TEXT)""", write=True)
q(f"""CREATE TABLE IF NOT EXISTS loan_payments(
  id {PK}, loan_id INTEGER, amount FLOAT, date TEXT)""", write=True)


def month_range(month: Optional[str]):
    """month = 'YYYY-MM'; defaults to the CURRENT month, so it rolls over by itself."""
    if month:
        try:
            y, m = map(int, month.split("-"))
            first = dt.date(y, m, 1)
        except ValueError:
            raise HTTPException(400, "month must be YYYY-MM")
    else:
        t = dt.date.today()
        first = dt.date(t.year, t.month, 1)
    return first, dt.date(first.year, first.month, monthrange(first.year, first.month)[1])


class TxIn(BaseModel):
    type: Literal["income", "expense"]
    amount: float = Field(gt=0)
    category: str = "General"
    note: str = ""
    date: Optional[dt.date] = None  # empty = today


class LoanIn(BaseModel):
    person: str
    direction: Literal["taken", "given"]  # taken = I owe; given = owed to me
    amount: float = Field(gt=0)
    due_date: Optional[dt.date] = None
    note: str = ""


class PayIn(BaseModel):
    amount: float = Field(gt=0)
    date: Optional[dt.date] = None


# ---------- transactions ----------
@app.post("/api/transactions")
def add_tx(t: TxIn):
    d = (t.date or dt.date.today()).isoformat()
    id_ = q("INSERT INTO transactions(type,amount,category,note,date) VALUES(?,?,?,?,?)",
            (t.type, t.amount, t.category.strip() or "General", t.note, d), write=True)
    return {"id": id_}


@app.get("/api/transactions")
def list_tx(month: Optional[str] = None):
    a, b = month_range(month)
    return q("SELECT * FROM transactions WHERE date BETWEEN ? AND ? ORDER BY date DESC, id DESC",
             (a.isoformat(), b.isoformat()))


@app.delete("/api/transactions/{id}")
def del_tx(id: int):
    q("DELETE FROM transactions WHERE id=?", (id,), write=True)
    return {"ok": True}


# ---------- loans ----------
@app.post("/api/loans")
def add_loan(l: LoanIn):
    id_ = q("INSERT INTO loans(person,direction,amount,due_date,note,created) VALUES(?,?,?,?,?,?)",
            (l.person, l.direction, l.amount, l.due_date.isoformat() if l.due_date else None,
             l.note, dt.date.today().isoformat()), write=True)
    return {"id": id_}


def loans_with_balance():
    rows = q("""SELECT l.*, COALESCE((SELECT SUM(amount) FROM loan_payments WHERE loan_id=l.id),0) AS paid
                FROM loans l ORDER BY l.due_date IS NULL, l.due_date""")
    for r in rows:
        r["outstanding"] = round(r["amount"] - r["paid"], 2)
    return rows


@app.get("/api/loans")
def list_loans():
    return loans_with_balance()


@app.post("/api/loans/{id}/payments")
def pay_loan(id: int, p: PayIn):
    q("INSERT INTO loan_payments(loan_id,amount,date) VALUES(?,?,?)",
      (id, p.amount, (p.date or dt.date.today()).isoformat()), write=True)
    return {"ok": True}


@app.delete("/api/loans/{id}")
def del_loan(id: int):
    q("DELETE FROM loan_payments WHERE loan_id=?", (id,), write=True)
    q("DELETE FROM loans WHERE id=?", (id,), write=True)
    return {"ok": True}


# ---------- summary + daily fund need ----------
@app.get("/api/summary")
def summary(month: Optional[str] = None):
    a, b = month_range(month)
    today = dt.date.today()
    rows = q("SELECT * FROM transactions WHERE date BETWEEN ? AND ?", (a.isoformat(), b.isoformat()))
    income = sum(r["amount"] for r in rows if r["type"] == "income")
    expense = sum(r["amount"] for r in rows if r["type"] == "expense")

    daily, cats = {}, {}
    for r in rows:
        d = daily.setdefault(r["date"], {"income": 0, "expense": 0})
        d[r["type"]] += r["amount"]
        if r["type"] == "expense":
            cats[r["category"]] = cats.get(r["category"], 0) + r["amount"]

    cash = q("""SELECT COALESCE(SUM(CASE WHEN type='income' THEN amount ELSE -amount END),0) AS v
                FROM transactions""", one=True)["v"]

    if today < a:
        elapsed, left = 1, (b - a).days + 1
    elif today > b:
        elapsed, left = (b - a).days + 1, 0
    else:
        elapsed, left = (today - a).days + 1, (b - today).days
    avg_daily = expense / elapsed

    loans = loans_with_balance()
    owe_due = sum(l["outstanding"] for l in loans if l["direction"] == "taken" and l["outstanding"] > 0
                  and l["due_date"] and l["due_date"] <= b.isoformat())
    owe_today = sum(l["outstanding"] for l in loans if l["direction"] == "taken" and l["outstanding"] > 0
                    and l["due_date"] and l["due_date"] <= today.isoformat())
    owed_to_me = sum(l["outstanding"] for l in loans if l["direction"] == "given")
    total_owe = sum(l["outstanding"] for l in loans if l["direction"] == "taken")

    need_rest_of_month = avg_daily * left + owe_due
    return {
        "month": a.strftime("%Y-%m"), "today": today.isoformat(),
        "income": income, "expense": expense, "net": income - expense, "cash_balance": cash,
        "daily": [{"date": k, **v} for k, v in sorted(daily.items())],
        "categories": sorted(({"category": k, "amount": v} for k, v in cats.items()),
                             key=lambda x: -x["amount"]),
        "fund": {
            "avg_daily_expense": round(avg_daily, 2), "days_left": left,
            "loan_due_today": owe_today, "daily_need_today": round(avg_daily + owe_today, 2),
            "loan_due_this_month": owe_due,
            "need_rest_of_month": round(need_rest_of_month, 2),
            "shortfall": round(max(0, need_rest_of_month - cash), 2),
            "i_owe_total": total_owe, "owed_to_me_total": owed_to_me,
        },
    }


@app.get("/api/export")
def export(month: Optional[str] = None):
    rows = list_tx(month)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["date", "type", "category", "amount", "note"])
    for r in rows:
        w.writerow([r["date"], r["type"], r["category"], r["amount"], r["note"]])
    name = month or dt.date.today().strftime("%Y-%m")
    return StreamingResponse(iter([buf.getvalue()]), media_type="text/csv",
                             headers={"Content-Disposition": f"attachment; filename=transactions-{name}.csv"})
