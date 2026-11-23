from __future__ import annotations
import csv, io, json, os, time, secrets, hashlib, hmac
from collections import Counter, defaultdict, deque
from decimal import Decimal, InvalidOperation
from datetime import datetime, timezone
from threading import Lock
from uuid import uuid4
import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, UploadFile, File, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, Response
from pydantic import BaseModel, Field

DB=os.environ.get("DATABASE_URL")
OWNER=os.environ.get("DATAFIX_OWNER_EMAIL","").strip().lower()
PASSWORD=os.environ.get("DATAFIX_OWNER_PASSWORD","")
if not DB or not OWNER or "@" not in OWNER or len(PASSWORD)<20:
    raise RuntimeError("DATABASE_URL and secure DATAFIX_OWNER_EMAIL / DATAFIX_OWNER_PASSWORD required")

def connect():
    return psycopg.connect(DB, row_factory=dict_row, connect_timeout=10)

def phash(p,salt=None):
    salt=salt or secrets.token_bytes(16)
    return salt.hex()+":"+hashlib.pbkdf2_hmac("sha256",p.encode(),salt,310000).hex()
def valid(p,stored):
    try:
        salt,digest=stored.split(":")
        return hmac.compare_digest(hashlib.pbkdf2_hmac("sha256",p.encode(),bytes.fromhex(salt),310000),bytes.fromhex(digest))
    except (ValueError,TypeError):return False
def digest(t):return hashlib.sha256(t.encode()).hexdigest()

def setup():
    with connect() as c:
        c.execute("CREATE TABLE IF NOT EXISTS organizations (id TEXT PRIMARY KEY,name TEXT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),email TEXT UNIQUE NOT NULL,password_hash TEXT NOT NULL,role TEXT NOT NULL CHECK(role IN ('owner','analyst','viewer')),disabled BOOLEAN NOT NULL DEFAULT FALSE)")
        c.execute("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL REFERENCES users(id),expires_at BIGINT NOT NULL)")
        c.execute("CREATE TABLE IF NOT EXISTS jobs (id TEXT PRIMARY KEY,org_id TEXT NOT NULL REFERENCES organizations(id),created_by TEXT NOT NULL,created_at TEXT NOT NULL,summary TEXT NOT NULL,results TEXT NOT NULL,duplicates TEXT NOT NULL)")
        c.execute("CREATE INDEX IF NOT EXISTS jobs_org ON jobs(org_id,created_at DESC)")
        c.execute("CREATE TABLE IF NOT EXISTS audit (id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,org_id TEXT NOT NULL,user_id TEXT NOT NULL,action TEXT NOT NULL,entity_id TEXT,created_at TEXT NOT NULL)")
        if c.execute("SELECT COUNT(*) AS n FROM users").fetchone()["n"]==0:
            org=str(uuid4());uid=str(uuid4())
            c.execute("INSERT INTO organizations VALUES(%s,%s)",(org,"DataFix Express"))
            c.execute("INSERT INTO users(id,org_id,email,password_hash,role) VALUES(%s,%s,%s,%s,'owner')",(uid,org,OWNER,phash(PASSWORD)))

setup()
app=FastAPI(title="DataFix Express",docs_url=None,redoc_url=None,openapi_url=None)
attempts=defaultdict(deque)
attempt_lock=Lock()
@app.middleware("http")
async def security(req,call_next):
    resp=await call_next(req)
    for k,v in {"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Cache-Control":"no-store","Content-Security-Policy":"default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'","Permissions-Policy":"camera=(), microphone=(), geolocation=()"}.items():resp.headers[k]=v
    return resp

@app.head("/")
def head():return Response(status_code=200)

@app.get("/health")
def health():return {"status":"ok","app":"datafix-express"}
@app.get("/ready")
def ready():
    try:
        with connect() as c:c.execute("SELECT 1")
    except Exception:raise HTTPException(503,"Database unavailable")
    return {"status":"ready"}

class Login(BaseModel):
    email:str=Field(min_length=3,max_length=250)
    password:str=Field(min_length=1,max_length=1024)

def user_from(authorization):
    if not authorization or not authorization.startswith("Bearer "):raise HTTPException(401,"Authentication required")
    token=authorization[7:]
    if len(token)>256:raise HTTPException(401,"Invalid session")
    with connect() as c:
        u=c.execute("SELECT u.id,u.org_id,u.email,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=%s AND s.expires_at>%s AND NOT u.disabled",(digest(token),int(time.time()))).fetchone()
    if not u:raise HTTPException(401,"Session expired")
    return u
def need(authorization,roles=None):
    u=user_from(authorization)
    if roles and u["role"] not in roles:raise HTTPException(403,"Insufficient permissions")
    return u
def audit(c,u,action,entity=None):
    c.execute("INSERT INTO audit(org_id,user_id,action,entity_id,created_at) VALUES(%s,%s,%s,%s,%s)",(u["org_id"],u["id"],action,entity,datetime.now(timezone.utc).isoformat()))

@app.post("/api/login")
def login(body:Login,request:Request):
    src=request.client.host if request.client else "unknown"
    now=time.monotonic()
    with attempt_lock:
        q=attempts[src]
        while q and q[0]<now-300:q.popleft()
        if len(q)>=12:raise HTTPException(429,"Too many attempts")
        q.append(now)
    with connect() as c:
        u=c.execute("SELECT * FROM users WHERE email=%s",(body.email.strip().lower(),)).fetchone()
        stored=u["password_hash"] if u else phash("unused-placeholder-password")
        if not valid(body.password,stored) or not u or u["disabled"]:raise HTTPException(401,"Invalid credentials")
        token=secrets.token_urlsafe(40)
        c.execute("DELETE FROM sessions WHERE expires_at<%s",(int(time.time()),))
        c.execute("INSERT INTO sessions VALUES(%s,%s,%s)",(digest(token),u["id"],int(time.time())+28800))
        return {"access_token":token,"role":u["role"],"email":u["email"],"expires_in":28800}
@app.get("/api/me")
def me(authorization:str|None=Header(None)):
    u=need(authorization);return {"email":u["email"],"role":u["role"]}
@app.post("/api/logout",status_code=204)
def logout(authorization:str|None=Header(None)):
    need(authorization)
    with connect() as c:c.execute("DELETE FROM sessions WHERE token_hash=%s",(digest(authorization[7:]),))
    return Response(status_code=204)

class NewUser(BaseModel):
    email:str=Field(min_length=3,max_length=250)
    password:str=Field(min_length=12,max_length=1024)
    role:str

@app.post("/api/users",status_code=201)
def create_user(body:NewUser,authorization:str|None=Header(None)):
    u=need(authorization,["owner"])
    if body.role not in ("analyst","viewer") or "@" not in body.email:raise HTTPException(422,"Invalid role or email")
    uid=str(uuid4())
    try:
        with connect() as c:
            c.execute("INSERT INTO users(id,org_id,email,password_hash,role) VALUES(%s,%s,%s,%s,%s)",(uid,u["org_id"],body.email.lower(),phash(body.password),body.role))
            audit(c,u,"user.created",uid)
    except psycopg.errors.UniqueViolation:raise HTTPException(409,"Email already registered")
    return {"id":uid,"role":body.role,"email":body.email.lower()}
@app.get("/api/users")
def users(authorization:str|None=Header(None)):
    u=need(authorization,["owner"])
    with connect() as c:return c.execute("SELECT id,email,role,disabled FROM users WHERE org_id=%s ORDER BY email",(u["org_id"],)).fetchall()
@app.get("/api/audit")
def logs(authorization:str|None=Header(None)):
    u=need(authorization,["owner"])
    with connect() as c:return c.execute("SELECT id,user_id,action,entity_id,created_at FROM audit WHERE org_id=%s ORDER BY id DESC LIMIT 100",(u["org_id"],)).fetchall()

def read_csv(data,required):
    if not data or len(data)>2_000_000 or b"\x00" in data:raise ValueError("File must be UTF-8 CSV, max 2 MB")
    try:content=data.decode("utf-8-sig")
    except UnicodeDecodeError:raise ValueError("Use UTF-8 CSV")
    try:
        reader=csv.DictReader(io.StringIO(content,newline=""),strict=True)
        if not reader.fieldnames or len(reader.fieldnames)!=len(set(reader.fieldnames)) or not set(required).issubset(reader.fieldnames):raise ValueError("Required columns: "+",".join(required))
        rows=[]
        for i,row in enumerate(reader):
            if i>=20000:raise ValueError("Maximum 20,000 rows")
            if None in row or any(v is None for v in row.values()):raise ValueError("Malformed CSV")
            rows.append({k:str(v).strip() for k,v in row.items()})
    except csv.Error:raise ValueError("Malformed CSV")
    if not rows:raise ValueError("CSV must contain data rows")
    return rows
def amount(v):
    try:d=Decimal(v.strip().replace(",",""))
    except InvalidOperation:raise ValueError("Invalid amount")
    if not d.is_finite() or abs(d)>Decimal("1000000000000") or d!=d.quantize(Decimal(".01")):raise ValueError("Invalid amount precision or range")
    return d.quantize(Decimal(".01"))
def reconcile(o_data,p_data):
    orders=read_csv(o_data,("order_id","amount"))
    payments=read_csv(p_data,("order_id","paid_amount"))
    for rows,k in ((orders,"amount"),(payments,"paid_amount")):
        for r in rows:
            if not r["order_id"] or len(r["order_id"])>128:raise ValueError("Invalid order ID")
            r["_amount"]=amount(r[k])
    oc=Counter(r["order_id"] for r in orders);pc=Counter(r["order_id"] for r in payments)
    duplicates=[{"source":src,"order_id":key,"count":n} for src,counts in (("orders",oc),("payments",pc)) for key,n in counts.items() if n>1]
    duplicates.sort(key=lambda r:(r["order_id"],r["source"]))
    ambiguous={r["order_id"] for r in duplicates}
    o={r["order_id"]:r["_amount"] for r in orders if r["order_id"] not in ambiguous}
    p={r["order_id"]:r["_amount"] for r in payments if r["order_id"] not in ambiguous}
    results=[]
    for key in sorted(set(o)|set(p)):
        a=o.get(key);b=p.get(key)
        status="matched" if a is not None and b is not None and a==b else "amount_variance" if a is not None and b is not None else "unpaid_order" if a is not None else "payment_without_order"
        results.append({"order_id":key,"order_amount":str(a) if a is not None else "","paid_amount":str(b) if b is not None else "","difference":str(b-a) if a is not None and b is not None else "","status":status})
    summary={status:sum(r["status"]==status for r in results) for status in ("matched","amount_variance","unpaid_order","payment_without_order")}
    summary.update(duplicate_keys=len(duplicates),excluded_ambiguous_ids=len(ambiguous),input_order_rows=len(orders),input_payment_rows=len(payments))
    return {"summary":summary,"results":results,"duplicates":duplicates}

@app.post("/api/jobs",status_code=201)
async def create_job(orders:UploadFile=File(...),payments:UploadFile=File(...),authorization:str|None=Header(None)):
    u=need(authorization,["owner","analyst"])
    if any(not f.filename or not f.filename.lower().endswith(".csv") for f in (orders,payments)):raise HTTPException(400,"CSV files only")
    a=await orders.read(2_000_001);b=await payments.read(2_000_001)
    try:r=reconcile(a,b)
    except ValueError as exc:raise HTTPException(422,str(exc))
    jid=str(uuid4());when=datetime.now(timezone.utc).isoformat()
    with connect() as c:
        c.execute("INSERT INTO jobs VALUES(%s,%s,%s,%s,%s,%s,%s)",(jid,u["org_id"],u["id"],when,json.dumps(r["summary"]),json.dumps(r["results"]),json.dumps(r["duplicates"])))
        audit(c,u,"job.created",jid)
    return {"id":jid,"created_at":when,"summary":r["summary"]}
@app.get("/api/jobs")
def jobs(authorization:str|None=Header(None)):
    u=need(authorization)
    with connect() as c:rows=c.execute("SELECT id,created_at,summary FROM jobs WHERE org_id=%s ORDER BY created_at DESC LIMIT 100",(u["org_id"],)).fetchall()
    return [{**r,"summary":json.loads(r["summary"])} for r in rows]
def job_or_404(job_id,u):
    with connect() as c:r=c.execute("SELECT * FROM jobs WHERE id=%s AND org_id=%s",(job_id,u["org_id"])).fetchone()
    if not r:raise HTTPException(404,"Job not found")
    return r
@app.get("/api/jobs/{job_id}")
def job(job_id:str,authorization:str|None=Header(None)):
    u=need(authorization);r=job_or_404(job_id,u)
    return {**r,"summary":json.loads(r["summary"]),"results":json.loads(r["results"]),"duplicates":json.loads(r["duplicates"])}
@app.get("/api/jobs/{job_id}/export/{kind}")
def export(job_id:str,kind:str,authorization:str|None=Header(None)):
    if kind not in ("results","duplicates"):raise HTTPException(404)
    u=need(authorization);r=job_or_404(job_id,u)
    columns=["order_id","order_amount","paid_amount","difference","status"] if kind=="results" else ["source","order_id","count"]
    out=io.StringIO(newline="");w=csv.DictWriter(out,fieldnames=columns,extrasaction="ignore");w.writeheader()
    for row in json.loads(r[kind]):
        w.writerow({k:("'"+str(v) if str(v).lstrip().startswith(("=","+","-","@","\t","\r")) and k!="difference" else v) for k,v in row.items()})
    return Response(content=out.getvalue(),media_type="text/csv; charset=utf-8",headers={"Content-Disposition":f'attachment; filename="datafix_{kind}.csv"'})
@app.delete("/api/jobs/{job_id}",status_code=204)
def delete(job_id:str,authorization:str|None=Header(None)):
    u=need(authorization,["owner","analyst"])
    with connect() as c:
        result=c.execute("DELETE FROM jobs WHERE id=%s AND org_id=%s",(job_id,u["org_id"]))
        if result.rowcount==0:raise HTTPException(404,"Job not found")
        audit(c,u,"job.deleted",job_id)
    return Response(status_code=204)

@app.get("/",response_class=HTMLResponse)
def index():
    return """<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>DataFix Express — Reconciliation workspace</title><style>
*{box-sizing:border-box}body{margin:0;font:16px system-ui,Arial,sans-serif;background:#0b1220;color:#e7eefb}header,main,footer{max-width:1100px;margin:auto;padding:22px}header{display:flex;align-items:center;justify-content:space-between}a{color:#7dd3fc}h1{font-size:clamp(32px,6vw,64px);margin:14px 0}p{line-height:1.6;color:#b6c7dd}.hero{padding:50px 0}.tag{color:#67e8f9;font-weight:700;letter-spacing:.06em}.panel{background:#162337;border:1px solid #30425a;border-radius:15px;padding:24px;margin:22px 0}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}.small{font-size:13px;color:#b6c7dd}input,button{font:inherit;border-radius:8px;padding:12px;margin:5px 0}input{background:#0b1220;border:1px solid #61748a;color:white;max-width:100%}input[type=file]{width:100%}button{border:0;background:#38bdf8;color:#07121d;cursor:pointer;font-weight:700}button.secondary{background:#334861;color:white}.hide{display:none}table{width:100%;border-collapse:collapse;font-size:14px}th,td{padding:10px;border-bottom:1px solid #334861;text-align:left;word-break:break-word}#message{white-space:pre-wrap;color:#fbbf24}.tablewrap{overflow:auto}footer{color:#96a8ba;font-size:13px}</style></head><body>
<header><strong>◈ DataFix Express</strong><a href="#workspace">Open workspace / مساحة العمل</a></header>
<main><section class="hero"><div class="tag">DATA AUTOMATION · FINANCIAL RECONCILIATION</div><h1>Find mismatches.<br>Fix reporting faster.</h1><p>Upload two CSV files to identify matched orders, payment differences, missing payments, and duplicate identifiers. ارفع ملف الطلبات والمدفوعات لاكتشاف الفروقات والتكرارات بسرعة.</p><div class="grid"><div class="panel"><b>Exact matching</b><p>Deterministic, auditable comparisons.</p></div><div class="panel"><b>Private workspace</b><p>Authenticated access and isolated records.</p></div><div class="panel"><b>Exportable output</b><p>Review results and download reports.</p></div></div></section>
<section class="panel" id="workspace"><h2>Workspace / مساحة العمل</h2><div id="loginbox"><form id="loginform"><label>Email <input id="email" type="email" required autocomplete="username"></label><label>Password <input id="password" type="password" required autocomplete="current-password"></label><button>Sign in / دخول</button></form></div><div id="appbox" class="hide"><p id="identity"></p><button class="secondary" id="logout">Sign out</button><h3>New reconciliation / مطابقة جديدة</h3><form id="jobform"><label>Orders CSV <span class="small">(order_id,amount)</span><input id="orders" type="file" accept=".csv" required></label><label>Payments CSV <span class="small">(order_id,paid_amount)</span><input id="payments" type="file" accept=".csv" required></label><button>Run reconciliation</button></form><div class="grid" id="stats"></div><h3>Recent runs</h3><button class="secondary" id="refresh">Refresh</button><div class="tablewrap"><table><thead><tr><th>Date</th><th>Matched</th><th>Variance</th><th>Unpaid</th><th>Actions</th></tr></thead><tbody id="history"></tbody></table></div><h3>Results</h3><div id="details" class="tablewrap"></div><p id="downloads"></p></div><p id="message" role="status"></p></section>
<section class="panel"><h2>CSV specification / شكل الملفات</h2><p>Orders: <code>order_id,amount</code> · Payments: <code>order_id,paid_amount</code>. UTF-8 encoding. Maximum 2 MB and 20,000 rows per file. Duplicate identifiers are excluded from primary matching and reported separately. The service is a technical reconciliation aid, not accounting advice.</p></section></main><footer>DataFix Express · Demo deployment · No customer payment or self-registration is enabled.</footer>
<script src="/ui.js" defer></script></body></html>"""

@app.get("/ui.js")
def ui():
    return Response(content=UI_JS,media_type="application/javascript")

UI_JS = r"""
let token=sessionStorage.getItem('datafix_token')||'';
const $=id=>document.getElementById(id);
const msg=s=>$('message').textContent=s;
const headers=()=>({'Authorization':'Bearer '+token});
async function api(path,opts={}){
  const r=await fetch(path,{...opts,headers:{...headers(),...(opts.headers||{})}});
  if(!r.ok){let d={};try{d=await r.json()}catch(e){};throw Error(d.detail||'Request failed: '+r.status)}
  if(r.status===204)return null;
  return r.json();
}
function escapeHtml(s){return String(s??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]))}
async function refresh(){
  const runs=await api('/api/jobs');
  $('history').innerHTML=runs.map(j=>'<tr><td>'+escapeHtml(j.created_at.slice(0,19))+'</td><td>'+j.summary.matched+'</td><td>'+j.summary.amount_variance+'</td><td>'+j.summary.unpaid_order+'</td><td><button data-view="'+escapeHtml(j.id)+'">View</button></td></tr>').join('');
  document.querySelectorAll('[data-view]').forEach(b=>b.onclick=()=>view(b.dataset.view));
}
async function view(id){
  const j=await api('/api/jobs/'+encodeURIComponent(id));
  $('stats').innerHTML=Object.entries(j.summary).map(([k,v])=>'<div class="panel"><b>'+escapeHtml(k)+'</b><h2>'+escapeHtml(v)+'</h2></div>').join('');
  $('details').innerHTML='<table><thead><tr><th>Order ID</th><th>Order</th><th>Payment</th><th>Difference</th><th>Status</th></tr></thead><tbody>'+j.results.slice(0,500).map(r=>'<tr>'+['order_id','order_amount','paid_amount','difference','status'].map(k=>'<td>'+escapeHtml(r[k])+'</td>').join('')+'</tr>').join('')+'</tbody></table>'+(j.results.length>500?'<p>Showing first 500 rows. Download full report.</p>':'');
  $('downloads').innerHTML='<button id="export">Download results CSV</button> <button id="dupes">Download duplicates CSV</button>';
  for(const [kind,el] of [['results','export'],['duplicates','dupes']])$(el).onclick=async()=>{
    const resp=await fetch('/api/jobs/'+encodeURIComponent(id)+'/export/'+kind,{headers:headers()});
    if(!resp.ok){msg('Export failed');return}
    const blob=await resp.blob();const url=URL.createObjectURL(blob);const a=document.createElement('a');a.href=url;a.download='datafix_'+kind+'.csv';a.click();URL.revokeObjectURL(url);
  };
}
async function initialize(){
  try{
    const me=await api('/api/me');$('loginbox').classList.add('hide');$('appbox').classList.remove('hide');$('identity').textContent=me.email+' ('+me.role+')';
    await refresh();
  }catch(e){token='';sessionStorage.removeItem('datafix_token');$('appbox').classList.add('hide');$('loginbox').classList.remove('hide')}
}
$('loginform').onsubmit=async e=>{
  e.preventDefault();msg('');
  try{const r=await fetch('/api/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:$('email').value,password:$('password').value})});const d=await r.json();if(!r.ok)throw Error(d.detail||'Sign in failed');token=d.access_token;sessionStorage.setItem('datafix_token',token);$('password').value='';await initialize()}catch(e){msg(e.message)}
};
$('jobform').onsubmit=async e=>{
  e.preventDefault();msg('Processing...');
  try{const form=new FormData();form.append('orders',$('orders').files[0]);form.append('payments',$('payments').files[0]);const j=await api('/api/jobs',{method:'POST',body:form});await refresh();await view(j.id);msg('Reconciliation completed')}catch(e){msg(e.message)}
};
$('logout').onclick=async()=>{try{await api('/api/logout',{method:'POST'})}catch(e){}token='';sessionStorage.removeItem('datafix_token');initialize();msg('Signed out')};
$('refresh').onclick=async()=>{try{await refresh();msg('Updated')}catch(e){msg(e.message)}};
initialize();
"""
