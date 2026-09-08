from __future__ import annotations
import os, json, sqlite3, secrets, hashlib, hmac, base64, mimetypes, re, time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from fastapi import FastAPI, Request, Response, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE = Path(__file__).resolve().parent
DATA_DIR = Path(os.getenv('DATA_DIR', BASE/'data'))
UPLOAD_DIR = Path(os.getenv('UPLOAD_DIR', BASE/'uploads'))
DB_PATH = Path(os.getenv('DB_PATH', DATA_DIR/'hrconnect.db'))
STATIC_DIR = BASE/'static'
DATA_DIR.mkdir(parents=True, exist_ok=True)
UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

MAX_UPLOAD = int(os.getenv('MAX_UPLOAD_MB','100')) * 1024 * 1024
ALLOWED_EXT = {'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.zip','.mp4','.webm','.png','.jpg','.jpeg','.csv','.txt'}
SESSION_TTL = int(os.getenv('SESSION_TTL_HOURS','12')) * 3600
COOKIE_SECURE = os.getenv('COOKIE_SECURE','0') == '1'
APP_SECRET = os.getenv('APP_SECRET') or 'dev-only-change-me-' + hashlib.sha256(str(BASE).encode()).hexdigest()

app = FastAPI(title='HR Connect Pakistan', version='1.0.0')
app.mount('/assets', StaticFiles(directory=STATIC_DIR), name='assets')

def db():
    c = sqlite3.connect(DB_PATH)
    c.row_factory = sqlite3.Row
    c.execute('PRAGMA foreign_keys=ON')
    c.execute('PRAGMA journal_mode=WAL')
    return c

def now(): return datetime.now(timezone.utc).isoformat()

def pw_hash(password: str, salt: Optional[bytes]=None) -> str:
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
    return base64.urlsafe_b64encode(salt).decode()+'.'+base64.urlsafe_b64encode(dk).decode()

def pw_verify(password: str, stored: str) -> bool:
    try:
        s,h = stored.split('.',1); salt=base64.urlsafe_b64decode(s.encode())
        return hmac.compare_digest(pw_hash(password,salt), stored)
    except Exception: return False

def sign_session(username: str) -> str:
    payload = f'{username}|{int(time.time())+SESSION_TTL}'
    sig = hmac.new(APP_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f'{payload}|{sig}'.encode()).decode()

def session_user(request: Request) -> Optional[str]:
    token=request.cookies.get('hrc_session')
    if not token: return None
    try:
        raw=base64.urlsafe_b64decode(token.encode()).decode(); username,exp,sig=raw.rsplit('|',2)
        payload=f'{username}|{exp}'
        good=hmac.new(APP_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig,good) or int(exp)<int(time.time()): return None
        return username
    except Exception: return None

def require_admin(request: Request) -> str:
    u=session_user(request)
    if not u: raise HTTPException(401,'Authentication required')
    with db() as c:
        if not c.execute('SELECT 1 FROM admins WHERE username=? AND active=1',(u,)).fetchone():
            raise HTTPException(401,'Invalid session')
    return u

def clean_name(name: str) -> str:
    name = re.sub(r'[^A-Za-z0-9._-]+','_',name or 'file')
    return name[:160] or 'file'

def init_db():
    with db() as c:
        c.executescript('''
        CREATE TABLE IF NOT EXISTS admins(id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, active INTEGER DEFAULT 1, created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL, updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS courses(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT DEFAULT '',price TEXT DEFAULT 'Enrollment',status TEXT DEFAULT 'Open',published INTEGER DEFAULT 1,sort_order INTEGER DEFAULT 0,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS resources(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT DEFAULT '',type TEXT DEFAULT 'PDF',free INTEGER DEFAULT 1,published INTEGER DEFAULT 1,upload_id INTEGER,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS jobs(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,company TEXT DEFAULT '',location TEXT DEFAULT '',employment_type TEXT DEFAULT '',experience TEXT DEFAULT '',salary TEXT DEFAULT '',description TEXT DEFAULT '',apply_info TEXT DEFAULT '',published INTEGER DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS services(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,description TEXT DEFAULT '',price TEXT DEFAULT '',published INTEGER DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS leads(id INTEGER PRIMARY KEY AUTOINCREMENT,type TEXT NOT NULL,name TEXT NOT NULL,contact TEXT NOT NULL,message TEXT DEFAULT '',status TEXT DEFAULT 'New',created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS uploads(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,kind TEXT NOT NULL,price TEXT DEFAULT 'Free',filename TEXT NOT NULL,stored_name TEXT NOT NULL,mime TEXT DEFAULT '',size INTEGER DEFAULT 0,public INTEGER DEFAULT 1,created_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS drafts(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,html TEXT NOT NULL,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sources(id INTEGER PRIMARY KEY AUTOINCREMENT,title TEXT NOT NULL,authority TEXT DEFAULT '',url TEXT DEFAULT '',jurisdiction TEXT DEFAULT '',rule_type TEXT DEFAULT '',effective_date TEXT DEFAULT '',verified_date TEXT DEFAULT '',notes TEXT DEFAULT '',active INTEGER DEFAULT 1,created_at TEXT NOT NULL,updated_at TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS audit_logs(id INTEGER PRIMARY KEY AUTOINCREMENT,actor TEXT NOT NULL,action TEXT NOT NULL,entity TEXT NOT NULL,entity_id TEXT DEFAULT '',details TEXT DEFAULT '',created_at TEXT NOT NULL);
        ''')
        default_settings={
            'brand':'HR Connect Pakistan','community':'','contact':'','otMultiplier':1.5,
            'eobiEmployee':0,'eobiEmployer':0,'pessiRate':0,'verification':'Not configured',
            'tagline':'Practical HR Tools, Resources & Career Solutions','announcement':'','announcementActive':False
        }
        for k,v in default_settings.items():
            c.execute('INSERT OR IGNORE INTO settings(key,value,updated_at) VALUES(?,?,?)',(k,json.dumps(v),now()))
        if not c.execute('SELECT 1 FROM admins LIMIT 1').fetchone():
            user=os.getenv('ADMIN_USERNAME','admin'); pwd=os.getenv('ADMIN_PASSWORD','ChangeThisBeforeDeploy!')
            c.execute('INSERT INTO admins(username,password_hash,created_at) VALUES(?,?,?)',(user,pw_hash(pwd),now()))
        if c.execute('SELECT COUNT(*) FROM courses').fetchone()[0]==0:
            seed=[('Live Practical HR Masterclass','Practical screen-share learning around employee relations, payroll operations, statutory awareness and HR reporting.','Enrollment','Featured'),('HR Operations Foundations','Build stronger HR systems around records, attendance, payroll inputs, documentation and controls.','Coming soon','Planned'),('Recruitment & Interview Mastery','Structured screening, behavioral interviewing, scorecards and better hiring decisions.','Coming soon','Planned')]
            for i,x in enumerate(seed): c.execute('INSERT INTO courses(title,description,price,status,sort_order,created_at,updated_at) VALUES(?,?,?,?,?,?,?)',(*x,i,now(),now()))
        if c.execute('SELECT COUNT(*) FROM resources').fetchone()[0]==0:
            seed=[('Interview Evaluation Scorecard','Structured evidence-based candidate assessment.','DOCX',1),('Monthly HR Checklist','A repeatable operating checklist for routine HR controls.','PDF',1),('HR KPI Formula Sheet','Core workforce metrics and formulas in one quick reference.','XLSX',1)]
            for x in seed: c.execute('INSERT INTO resources(title,description,type,free,created_at,updated_at) VALUES(?,?,?,?,?,?)',(*x,now(),now()))
        if c.execute('SELECT COUNT(*) FROM services').fetchone()[0]==0:
            seed=[('Recruitment Support','Candidate sourcing, CV screening, shortlisting and initial interviews.','Custom'),('CV & LinkedIn Services','Professional CV review, rewrite and LinkedIn optimization.','Custom'),('HR Training & Masterclasses','Practical HR learning for professionals and teams.','Custom')]
            for x in seed: c.execute('INSERT INTO services(title,description,price,created_at,updated_at) VALUES(?,?,?,?,?)',(*x,now(),now()))

init_db()

@app.middleware('http')
async def security_headers(request: Request, call_next):
    resp=await call_next(request)
    resp.headers['X-Content-Type-Options']='nosniff'
    resp.headers['X-Frame-Options']='SAMEORIGIN'
    resp.headers['Referrer-Policy']='strict-origin-when-cross-origin'
    resp.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()'
    resp.headers['Content-Security-Policy']="default-src 'self' 'unsafe-inline' data: blob:; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self';"
    return resp

@app.get('/', response_class=HTMLResponse)
def home(): return FileResponse(STATIC_DIR/'index.html')

@app.get('/health')
def health(): return {'ok':True,'time':now(),'db':str(DB_PATH.name)}

@app.get('/robots.txt')
def robots():
    return Response('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/admin\nSitemap: /sitemap.xml\n',media_type='text/plain')

@app.get('/sitemap.xml')
def sitemap(request:Request):
    base=str(request.base_url).rstrip('/')
    urls=['/']
    xml='<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(f'<url><loc>{base}{u}</loc></url>' for u in urls)+'</urlset>'
    return Response(xml,media_type='application/xml')


def settings_dict(c):
    out={}
    for r in c.execute('SELECT key,value FROM settings'):
        try: out[r['key']]=json.loads(r['value'])
        except: out[r['key']]=r['value']
    return out

def rows(c, table, where='1=1', params=()):
    return [dict(r) for r in c.execute(f'SELECT * FROM {table} WHERE {where} ORDER BY id DESC',params).fetchall()]

@app.get('/api/public/state')
def public_state():
    with db() as c:
        return {
            'settings':settings_dict(c),
            'courses':[{'id':r['id'],'title':r['title'],'desc':r['description'],'price':r['price'],'status':r['status']} for r in c.execute('SELECT * FROM courses WHERE published=1 ORDER BY sort_order,id DESC')],
            'resources':[{'id':r['id'],'title':r['title'],'desc':r['description'],'type':r['type'],'free':bool(r['free']),'upload_id':r['upload_id']} for r in c.execute('SELECT * FROM resources WHERE published=1 ORDER BY id DESC')],
            'jobs':rows(c,'jobs','published=1'),
            'services':rows(c,'services','published=1')
        }

@app.get('/api/public/uploads')
def public_uploads():
    with db() as c:
        rs=c.execute('SELECT id,title,kind,price,filename,mime,size,created_at FROM uploads WHERE public=1 ORDER BY id DESC').fetchall()
        return [dict(x) for x in rs]

class LeadIn(BaseModel):
    type:str; name:str; contact:str; message:str=''
@app.post('/api/leads')
def create_lead(x:LeadIn):
    if len(x.name.strip())<2 or len(x.contact.strip())<3: raise HTTPException(400,'Name and contact are required')
    with db() as c:
        cur=c.execute('INSERT INTO leads(type,name,contact,message,created_at) VALUES(?,?,?,?,?)',(x.type[:120],x.name[:120],x.contact[:180],x.message[:2000],now()))
        return {'ok':True,'id':cur.lastrowid}

class LoginIn(BaseModel): username:str; password:str
@app.post('/api/admin/login')
def login(x:LoginIn,response:Response):
    with db() as c:
        r=c.execute('SELECT * FROM admins WHERE username=? AND active=1',(x.username,)).fetchone()
        if not r or not pw_verify(x.password,r['password_hash']): raise HTTPException(401,'Invalid username or password')
    response.set_cookie('hrc_session',sign_session(x.username),httponly=True,samesite='lax',secure=COOKIE_SECURE,max_age=SESSION_TTL,path='/')
    return {'ok':True,'username':x.username}

@app.post('/api/admin/logout')
def logout(response:Response):
    response.delete_cookie('hrc_session',path='/'); return {'ok':True}

@app.get('/api/admin/me')
def me(request:Request): return {'username':require_admin(request)}

@app.get('/api/admin/dashboard')
def dashboard(request:Request):
    require_admin(request)
    with db() as c:
        return {k:c.execute(f'SELECT COUNT(*) FROM {k}').fetchone()[0] for k in ['courses','resources','jobs','services','leads','uploads','drafts','sources']}

@app.get('/api/admin/settings')
def get_settings(request:Request):
    require_admin(request)
    with db() as c:return settings_dict(c)

@app.put('/api/admin/settings')
async def put_settings(request:Request):
    u=require_admin(request); payload=await request.json()
    allowed={'brand','community','contact','otMultiplier','eobiEmployee','eobiEmployer','pessiRate','verification','tagline','announcement','announcementActive'}
    with db() as c:
        for k,v in payload.items():
            if k in allowed:c.execute('INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at',(k,json.dumps(v),now()))
        c.execute('INSERT INTO audit_logs(actor,action,entity,details,created_at) VALUES(?,?,?,?,?)',(u,'update','settings',','.join(payload.keys()),now()))
    return {'ok':True}

TABLE_FIELDS={
'courses':['title','description','price','status','published','sort_order'],
'resources':['title','description','type','free','published','upload_id'],
'jobs':['title','company','location','employment_type','experience','salary','description','apply_info','published'],
'services':['title','description','price','published'],
'sources':['title','authority','url','jurisdiction','rule_type','effective_date','verified_date','notes','active'],
}

def safe_table(t):
    if t not in TABLE_FIELDS: raise HTTPException(404,'Unknown collection')
    return t

@app.get('/api/admin/content/{table}')
def list_table(table:str,request:Request):
    require_admin(request); t=safe_table(table)
    with db() as c:return rows(c,t)

@app.post('/api/admin/content/{table}')
async def create_table(table:str,request:Request):
    u=require_admin(request); t=safe_table(table); data=await request.json(); fields=[f for f in TABLE_FIELDS[t] if f in data]
    if 'title' in TABLE_FIELDS[t] and not str(data.get('title','')).strip(): raise HTTPException(400,'Title required')
    if not fields: raise HTTPException(400,'No valid fields')
    vals=[data[f] for f in fields]; cols=','.join(fields)+',created_at,updated_at'; qs=','.join('?' for _ in fields)+',?,?'
    with db() as c:
        cur=c.execute(f'INSERT INTO {t}({cols}) VALUES({qs})',(*vals,now(),now())); rid=cur.lastrowid
        c.execute('INSERT INTO audit_logs(actor,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)',(u,'create',t,str(rid),now()))
    return {'ok':True,'id':rid}

@app.put('/api/admin/content/{table}/{rid}')
async def update_table(table:str,rid:int,request:Request):
    u=require_admin(request); t=safe_table(table); data=await request.json(); fields=[f for f in TABLE_FIELDS[t] if f in data]
    if not fields: raise HTTPException(400,'No valid fields')
    setsql=','.join(f'{f}=?' for f in fields)+',updated_at=?'; vals=[data[f] for f in fields]+[now(),rid]
    with db() as c:
        c.execute(f'UPDATE {t} SET {setsql} WHERE id=?',vals)
        c.execute('INSERT INTO audit_logs(actor,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)',(u,'update',t,str(rid),now()))
    return {'ok':True}

@app.delete('/api/admin/content/{table}/{rid}')
def delete_table(table:str,rid:int,request:Request):
    u=require_admin(request); t=safe_table(table)
    with db() as c:
        c.execute(f'DELETE FROM {t} WHERE id=?',(rid,)); c.execute('INSERT INTO audit_logs(actor,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)',(u,'delete',t,str(rid),now()))
    return {'ok':True}

@app.get('/api/admin/leads')
def admin_leads(request:Request):
    require_admin(request)
    with db() as c:return rows(c,'leads')

@app.patch('/api/admin/leads/{rid}')
async def patch_lead(rid:int,request:Request):
    require_admin(request); d=await request.json(); status=str(d.get('status','New'))[:40]
    with db() as c:c.execute('UPDATE leads SET status=? WHERE id=?',(status,rid))
    return {'ok':True}

@app.delete('/api/admin/leads/{rid}')
def del_lead(rid:int,request:Request):
    require_admin(request)
    with db() as c:c.execute('DELETE FROM leads WHERE id=?',(rid,))
    return {'ok':True}

@app.get('/api/admin/uploads')
def admin_uploads(request:Request):
    require_admin(request)
    with db() as c:return rows(c,'uploads')

@app.post('/api/admin/uploads')
async def upload_file(request:Request,file:UploadFile=File(...),title:str=Form(''),kind:str=Form('Resource'),price:str=Form('Free'),public:int=Form(1)):
    u=require_admin(request); original=clean_name(file.filename or 'file'); ext=Path(original).suffix.lower()
    if ext not in ALLOWED_EXT: raise HTTPException(400,'File type not allowed')
    data=await file.read(MAX_UPLOAD+1)
    if len(data)>MAX_UPLOAD: raise HTTPException(413,f'Max upload size is {MAX_UPLOAD//1024//1024} MB')
    stored=f'{int(time.time())}_{secrets.token_hex(8)}{ext}'; path=UPLOAD_DIR/stored; path.write_bytes(data)
    mime=file.content_type or mimetypes.guess_type(original)[0] or 'application/octet-stream'
    with db() as c:
        cur=c.execute('INSERT INTO uploads(title,kind,price,filename,stored_name,mime,size,public,created_at) VALUES(?,?,?,?,?,?,?,?,?)',(title.strip() or original,kind[:80],price[:80],original,stored,mime,len(data),1 if public else 0,now()))
        rid=cur.lastrowid;c.execute('INSERT INTO audit_logs(actor,action,entity,entity_id,created_at) VALUES(?,?,?,?,?)',(u,'upload','uploads',str(rid),now()))
    return {'ok':True,'id':rid}

@app.delete('/api/admin/uploads/{rid}')
def delete_upload(rid:int,request:Request):
    require_admin(request)
    with db() as c:
        r=c.execute('SELECT stored_name FROM uploads WHERE id=?',(rid,)).fetchone()
        if r:
            try:(UPLOAD_DIR/r['stored_name']).unlink(missing_ok=True)
            except:pass
        c.execute('UPDATE resources SET upload_id=NULL WHERE upload_id=?',(rid,));c.execute('DELETE FROM uploads WHERE id=?',(rid,))
    return {'ok':True}

@app.get('/download/{rid}')
def download(rid:int,request:Request):
    with db() as c:r=c.execute('SELECT * FROM uploads WHERE id=?',(rid,)).fetchone()
    if not r: raise HTTPException(404,'File not found')
    if not r['public'] and not session_user(request): raise HTTPException(403,'Private file')
    path=UPLOAD_DIR/r['stored_name']
    if not path.exists(): raise HTTPException(404,'Stored file missing')
    return FileResponse(path,media_type=r['mime'] or 'application/octet-stream',filename=r['filename'])

class DraftIn(BaseModel): title:str; html:str
@app.get('/api/admin/drafts')
def list_drafts(request:Request):
    require_admin(request)
    with db() as c:return rows(c,'drafts')
@app.post('/api/admin/drafts')
def create_draft(x:DraftIn,request:Request):
    require_admin(request)
    with db() as c:
        cur=c.execute('INSERT INTO drafts(title,html,created_at,updated_at) VALUES(?,?,?,?)',(x.title[:180],x.html,now(),now()));return {'ok':True,'id':cur.lastrowid}
@app.delete('/api/admin/drafts/{rid}')
def delete_draft(rid:int,request:Request):
    require_admin(request)
    with db() as c:c.execute('DELETE FROM drafts WHERE id=?',(rid,))
    return {'ok':True}

class PasswordChange(BaseModel): current_password:str; new_password:str
@app.post('/api/admin/change-password')
def change_password(x:PasswordChange,request:Request):
    u=require_admin(request)
    if len(x.new_password)<12: raise HTTPException(400,'New password must be at least 12 characters')
    with db() as c:
        r=c.execute('SELECT password_hash FROM admins WHERE username=?',(u,)).fetchone()
        if not r or not pw_verify(x.current_password,r['password_hash']): raise HTTPException(400,'Current password is incorrect')
        c.execute('UPDATE admins SET password_hash=? WHERE username=?',(pw_hash(x.new_password),u))
    return {'ok':True}

@app.get('/admin', response_class=HTMLResponse)
def admin_page(): return FileResponse(STATIC_DIR/'admin.html')

if __name__=='__main__':
    import uvicorn
    uvicorn.run('app:app',host=os.getenv('HOST','127.0.0.1'),port=int(os.getenv('PORT','8000')),reload=False)
