"""Cloud copy of the subscriber pages: login + each subscriber's own view-only dashboard + his stop button.

Runs on any free Python host (Render, Railway, Koyeb, ...). It keeps nothing on disk: the trading PC pushes the
subscribers' logins (password hashes only) and live numbers to POST /sync every few seconds, and collects the
"stop trading" clicks in the reply. If this server restarts, the PC fills it again on its next push.

Environment variables:
  (none required) — the PC's token is checked against the SHA-256 built in below
  SYNC_TOKEN / SYNC_TOKEN_SHA256  optional — use a different token than the built-in one
  SESSION_SECRET  optional — keeps users logged in across restarts
"""
import os, time, hmac, hashlib, secrets, datetime as dt
from collections import defaultdict, deque

from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse, RedirectResponse, JSONResponse
from fastapi.templating import Jinja2Templates
from itsdangerous import URLSafeTimedSerializer, BadSignature

from i18n import T

HERE = os.path.dirname(os.path.abspath(__file__))
# The PC proves itself with a secret token; only its SHA-256 is stored here, so this file can be public.
# SYNC_TOKEN (plain) or SYNC_TOKEN_SHA256 in the environment override the built-in hash.
SYNC_HASH = (hashlib.sha256(os.environ["SYNC_TOKEN"].encode()).hexdigest() if os.environ.get("SYNC_TOKEN")
             else os.environ.get("SYNC_TOKEN_SHA256", "b667ee12e9eace0e37862bde76140c8503a01dfb27c0d9f25c21d42f4dc6b09f"))
# login cookies: a fresh random key per start unless SESSION_SECRET is set (a restart just asks users to log in again)
signer = URLSafeTimedSerializer(os.environ.get("SESSION_SECRET") or secrets.token_hex(32), salt="session")
app = FastAPI(docs_url=None, redoc_url=None, openapi_url=None)
tpl = Jinja2Templates(directory=os.path.join(HERE, "templates"))
COOKIE = "hat_session"

# ------------------------------------------------------------------ data pushed by the PC (memory only)
DB = {"users": {}, "support": "", "synced_at": None}      # users: username -> record
PENDING_STOPS = set()                                     # client ids the subscribers asked to stop


def utcnow():
    return dt.datetime.now(dt.timezone.utc)


def check_password(pw, stored):
    try:
        salt, h = stored.split("$")
        return hmac.compare_digest(hashlib.scrypt(pw.encode(), salt=bytes.fromhex(salt), n=2 ** 14, r=8, p=1).hex(), h)
    except Exception:
        return False


ATTEMPTS = defaultdict(deque)


def rate_limited(key, limit=8, window=600):
    q = ATTEMPTS[key]; now = time.time()
    while q and now - q[0] > window:
        q.popleft()
    q.append(now)
    return len(q) > limit


def client_ip(req):
    return req.headers.get("cf-connecting-ip") or (req.headers.get("x-forwarded-for") or "").split(",")[0].strip() \
        or (req.client.host if req.client else "?")


def session(req):
    try:
        return signer.loads(req.cookies.get(COOKIE, ""), max_age=30 * 86400)
    except (BadSignature, Exception):
        return {}


def set_session(resp, req, s):
    secure = req.headers.get("x-forwarded-proto") == "https" or req.url.scheme == "https"
    resp.set_cookie(COOKIE, signer.dumps(s), max_age=30 * 86400, httponly=True, samesite="lax", secure=secure)


def lang_of(req):
    l = req.cookies.get("lang")
    return l if l in T else "ar"


def render(req, name, status=200, **ctx):
    s = session(req)
    if not s.get("csrf"):
        s["csrf"] = secrets.token_urlsafe(16)
    l = lang_of(req)
    resp = tpl.TemplateResponse(req, name, dict(t=T[l], lang=l, sess=s, csrf=s["csrf"], support=DB["support"], **ctx),
                                status_code=status)
    set_session(resp, req, s)
    return resp


def redirect(req, to, **upd):
    s = session(req); s.update(upd)
    r = RedirectResponse(to, status_code=303)
    set_session(r, req, s)
    return r


def csrf_ok(req, token):
    return bool(token) and hmac.compare_digest(session(req).get("csrf", ""), token)


def current_user(req):
    u = session(req).get("u")
    rec = DB["users"].get(u) if u else None
    # a password change on the PC logs the old sessions out
    if rec and session(req).get("pv") != rec["pass_hash"][-12:]:
        return None
    return rec


def human_left(exp, t):
    s = int((exp - utcnow()).total_seconds())
    if s <= 0:
        return t["expired"]
    days, s = divmod(s, 86400); h = s // 3600
    return f"{days} {t['days']} {h}h" if days else f"{h}h {(s % 3600) // 60}m"


def stale():
    return DB["synced_at"] is None or (utcnow() - DB["synced_at"]).total_seconds() > 120


@app.middleware("http")
async def security_headers(req, call_next):
    r = await call_next(req)
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["Referrer-Policy"] = "same-origin"
    return r


# ------------------------------------------------------------------ pages
@app.get("/", response_class=HTMLResponse)
def home(req: Request):
    return RedirectResponse("/dashboard" if current_user(req) else "/login", status_code=303)


@app.get("/lang/{l}")
def set_lang(req: Request, l: str):
    r = RedirectResponse(req.headers.get("referer") or "/", status_code=303)
    if l in T:
        r.set_cookie("lang", l, max_age=365 * 86400, samesite="lax")
    return r


@app.get("/login", response_class=HTMLResponse)
def login_page(req: Request):
    return render(req, "login.html", err=None, email="")


@app.post("/login", response_class=HTMLResponse)
def login(req: Request, email: str = Form(""), password: str = Form(""), csrf: str = Form("")):
    t = T[lang_of(req)]
    name = email.strip().lower()
    if not csrf_ok(req, csrf):
        return render(req, "login.html", 400, err=t["err_csrf"], email=email)
    if rate_limited("li:" + client_ip(req)) or rate_limited("le:" + name, 10):
        return render(req, "login.html", 429, err=t["err_rate"], email=email)
    rec = DB["users"].get(name)
    if not rec or not check_password(password, rec["pass_hash"]):
        return render(req, "login.html", 401, err=t["err_login_user"], email=email)
    return redirect(req, "/dashboard", u=name, pv=rec["pass_hash"][-12:], uid=1, csrf=secrets.token_urlsafe(16))


@app.get("/logout")
def logout(req: Request):
    r = RedirectResponse("/login", status_code=303)
    r.delete_cookie(COOKIE)
    return r


def view(rec):
    c = rec.get("client")
    exp = dt.datetime.fromisoformat(rec["expires_at"]) if rec.get("expires_at") else None
    if c and c["id"] in PENDING_STOPS:
        c = dict(c, paused=1)
    state = "stopped" if c and c.get("paused") else rec.get("state")
    return c, exp, state


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(req: Request):
    u = current_user(req)
    if not u:
        return RedirectResponse("/login", status_code=303)
    t = T[lang_of(req)]
    s = session(req); msg = s.pop("flash", None)
    c, exp, state = view(u)
    active = bool(exp and exp > utcnow())
    resp = render(req, "dashboard.html", user={"name": u.get("name"), "email": u["username"]}, client=c,
                  st={"positions": u.get("positions") or []}, state=state, active=active, exp=exp,
                  left=human_left(exp, t) if exp else None, msg=msg, k=u.get("stats") or {},
                  stale=stale(), synced=DB["synced_at"])
    s2 = session(req); s2.pop("flash", None); s2["csrf"] = resp.context["csrf"]; set_session(resp, req, s2)
    return resp


@app.get("/api/status")
def api_status(req: Request):
    u = current_user(req)
    if not u:
        return JSONResponse({}, status_code=401)
    return dict(u.get("stats") or {}, positions=u.get("positions") or [], stale=stale())


@app.post("/stop")
def stop_trading(req: Request, csrf: str = Form("")):
    u = current_user(req)
    if not u:
        return RedirectResponse("/login", status_code=303)
    t = T[lang_of(req)]
    if not csrf_ok(req, csrf):
        return redirect(req, "/dashboard", flash=("err", t["err_csrf"]))
    if u.get("client"):
        PENDING_STOPS.add(u["client"]["id"])     # handed to the PC on its next sync (a few seconds)
    return redirect(req, "/dashboard", flash=("ok", t["stopped_ok"]))


# ------------------------------------------------------------------ PC <-> cloud
@app.post("/sync")
async def sync(req: Request):
    auth = req.headers.get("authorization", "")
    given = auth[7:] if auth.startswith("Bearer ") else ""
    if not (SYNC_HASH and given and hmac.compare_digest(hashlib.sha256(given.encode()).hexdigest(), SYNC_HASH)):
        return JSONResponse({"error": "unauthorized"}, status_code=401)
    body = await req.json()
    users = {}
    for r in body.get("users", []):
        name = str(r.get("username", "")).strip().lower()
        if name and r.get("pass_hash"):
            users[name] = dict(r, username=name)
    DB["users"] = users
    DB["support"] = body.get("support") or ""
    DB["synced_at"] = utcnow()
    for cid in body.get("applied_stops", []):
        PENDING_STOPS.discard(cid)
    return {"stops": sorted(PENDING_STOPS), "users": len(users)}


@app.get("/health")
def health():
    return {"ok": True, "users": len(DB["users"]), "synced_at": DB["synced_at"].isoformat() if DB["synced_at"] else None}
