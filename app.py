from __future__ import annotations
import os, json, secrets, hashlib, hmac, base64, mimetypes, re, time
from pathlib import Path
from datetime import datetime, timezone
from typing import Optional
from urllib import request as urequest, parse as uparse, error as uerror
from fastapi import FastAPI, Request, Response, UploadFile, File, Form, HTTPException
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

BASE=Path(__file__).resolve().parent
STATIC_DIR=BASE/'static'
STATIC_DIR.mkdir(parents=True,exist_ok=True)
# Render build copies root HTML into static; local package already has static files.
MAX_UPLOAD=int(os.getenv('MAX_UPLOAD_MB','100'))*1024*1024
ALLOWED_EXT={'.pdf','.doc','.docx','.xls','.xlsx','.ppt','.pptx','.zip','.mp4','.webm','.png','.jpg','.jpeg','.csv','.txt'}
SESSION_TTL=int(os.getenv('SESSION_TTL_HOURS','12'))*3600
COOKIE_SECURE=os.getenv('COOKIE_SECURE','0')=='1'
APP_SECRET=os.getenv('APP_SECRET') or 'dev-only-change-me-'+hashlib.sha256(str(BASE).encode()).hexdigest()
SUPABASE_URL=os.getenv('SUPABASE_URL','').rstrip('/')
SUPABASE_KEY=os.getenv('SUPABASE_SERVICE_ROLE_KEY','') or os.getenv('SUPABASE_SECRET_KEY','')
BUCKET=os.getenv('SUPABASE_STORAGE_BUCKET','hr-connect-files')

app=FastAPI(title='HR Connect Pakistan',version='2.0.0')
app.mount('/assets',StaticFiles(directory=STATIC_DIR),name='assets')

def now(): return datetime.now(timezone.utc).isoformat()
def need_supabase():
    if not SUPABASE_URL or not SUPABASE_KEY: raise HTTPException(503,'Supabase backend is not configured')
def sb_headers(extra=None):
    h={'apikey':SUPABASE_KEY,'Authorization':f'Bearer {SUPABASE_KEY}'}
    if extra:h.update(extra)
    return h
def sb_call(method,path,params=None,data=None,raw=None,headers=None,timeout=30):
    need_supabase(); url=SUPABASE_URL+path
    if params: url+='?'+uparse.urlencode(params,doseq=True)
    h=sb_headers(headers or {})
    body=raw
    if data is not None:
        body=json.dumps(data).encode(); h.setdefault('Content-Type','application/json')
    req=urequest.Request(url,data=body,headers=h,method=method)
    try:
        with urequest.urlopen(req,timeout=timeout) as r:
            content=r.read(); ctype=r.headers.get('Content-Type','')
            if 'application/json' in ctype and content:return json.loads(content)
            return content
    except uerror.HTTPError as e:
        msg=e.read().decode(errors='replace')
        raise HTTPException(e.code,f'Supabase request failed: {msg[:500]}')
    except Exception as e: raise HTTPException(503,f'Supabase unavailable: {str(e)[:200]}')
def select(table,filters=None,order='id.desc',columns='*',limit=None):
    p={'select':columns}
    if filters:p.update(filters)
    if order:p['order']=order
    if limit:p['limit']=str(limit)
    return sb_call('GET',f'/rest/v1/{table}',p) or []
def insert(table,data):
    r=sb_call('POST',f'/rest/v1/{table}',data=data,headers={'Prefer':'return=representation'}) or []
    return r[0] if isinstance(r,list) and r else {}
def patch(table,rid,data):
    return sb_call('PATCH',f'/rest/v1/{table}',{'id':f'eq.{rid}'},data=data,headers={'Prefer':'return=representation'})
def delete(table,rid): return sb_call('DELETE',f'/rest/v1/{table}',{'id':f'eq.{rid}'},headers={'Prefer':'return=minimal'})
def count(table):
    h={'Prefer':'count=exact','Range':'0-0'}; need_supabase(); url=SUPABASE_URL+f'/rest/v1/{table}?select=id'
    req=urequest.Request(url,headers=sb_headers(h),method='HEAD')
    try:
        with urequest.urlopen(req,timeout=15) as r:
            cr=r.headers.get('Content-Range','0-0/0'); return int(cr.split('/')[-1]) if '/' in cr and cr.split('/')[-1].isdigit() else 0
    except Exception:return len(select(table,columns='id'))

def pw_hash(password:str,salt:Optional[bytes]=None)->str:
    salt=salt or secrets.token_bytes(16); dk=hashlib.scrypt(password.encode(),salt=salt,n=2**14,r=8,p=1,dklen=32)
    return base64.urlsafe_b64encode(salt).decode()+'.'+base64.urlsafe_b64encode(dk).decode()
def pw_verify(password:str,stored:str)->bool:
    try:
        s,_=stored.split('.',1); return hmac.compare_digest(pw_hash(password,base64.urlsafe_b64decode(s.encode())),stored)
    except:return False
def sign_session(username:str)->str:
    payload=f'{username}|{int(time.time())+SESSION_TTL}'; sig=hmac.new(APP_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
    return base64.urlsafe_b64encode(f'{payload}|{sig}'.encode()).decode()
def session_user(req:Request)->Optional[str]:
    token=req.cookies.get('hrc_session')
    if not token:return None
    try:
        raw=base64.urlsafe_b64decode(token.encode()).decode(); username,exp,sig=raw.rsplit('|',2); payload=f'{username}|{exp}'
        good=hmac.new(APP_SECRET.encode(),payload.encode(),hashlib.sha256).hexdigest()
        return username if hmac.compare_digest(sig,good) and int(exp)>=int(time.time()) else None
    except:return None
def require_admin(req:Request)->str:
    u=session_user(req)
    if not u:raise HTTPException(401,'Authentication required')
    rs=select('admins',{'username':f'eq.{u}','active':'eq.1'},limit=1)
    if not rs:raise HTTPException(401,'Invalid session')
    return u
def clean_name(name:str)->str:
    return (re.sub(r'[^A-Za-z0-9._-]+','_',name or 'file')[:160] or 'file')

def audit(actor,action,entity,entity_id='',details=''):
    insert('audit_logs',{'actor':actor,'action':action,'entity':entity,'entity_id':str(entity_id),'details':details,'created_at':now()})
def init_db():
    if not SUPABASE_URL or not SUPABASE_KEY:return
    defaults={'brand':'HR Connect Pakistan','community':'','contact':'','otMultiplier':1.5,'eobiEmployee':0,'eobiEmployer':0,'pessiRate':0,'verification':'Not configured','tagline':'Practical HR Tools, Resources & Career Solutions','announcement':'','announcementActive':False}
    existing={r['key'] for r in select('settings',order='key.asc')}
    for k,v in defaults.items():
        if k not in existing:insert('settings',{'key':k,'value':json.dumps(v),'updated_at':now()})
    if not select('admins',limit=1):
        insert('admins',{'username':os.getenv('ADMIN_USERNAME','admin'),'password_hash':pw_hash(os.getenv('ADMIN_PASSWORD','ChangeThisBeforeDeploy!')),'active':1,'created_at':now()})
    if count('courses')==0:
        for i,x in enumerate([('Live Practical HR Masterclass','Practical screen-share learning around employee relations, payroll operations, statutory awareness and HR reporting.','Enrollment','Featured'),('HR Operations Foundations','Build stronger HR systems around records, attendance, payroll inputs, documentation and controls.','Coming soon','Planned'),('Recruitment & Interview Mastery','Structured screening, behavioral interviewing, scorecards and better hiring decisions.','Coming soon','Planned')]):
            insert('courses',{'title':x[0],'description':x[1],'price':x[2],'status':x[3],'published':1,'sort_order':i,'created_at':now(),'updated_at':now()})
    if count('resources')==0:
        for x in [('Interview Evaluation Scorecard','Structured evidence-based candidate assessment.','DOCX',1),('Monthly HR Checklist','A repeatable operating checklist for routine HR controls.','PDF',1),('HR KPI Formula Sheet','Core workforce metrics and formulas in one quick reference.','XLSX',1)]:
            insert('resources',{'title':x[0],'description':x[1],'type':x[2],'free':x[3],'published':1,'created_at':now(),'updated_at':now()})
    if count('services')==0:
        for x in [('Recruitment Support','Candidate sourcing, CV screening, shortlisting and initial interviews.','Custom'),('CV & LinkedIn Services','Professional CV review, rewrite and LinkedIn optimization.','Custom'),('HR Training & Masterclasses','Practical HR learning for professionals and teams.','Custom')]:
            insert('services',{'title':x[0],'description':x[1],'price':x[2],'published':1,'created_at':now(),'updated_at':now()})

@app.on_event('startup')
def startup(): init_db()
@app.middleware('http')
async def security_headers(req:Request,call_next):
    resp=await call_next(req); resp.headers['X-Content-Type-Options']='nosniff';resp.headers['X-Frame-Options']='SAMEORIGIN';resp.headers['Referrer-Policy']='strict-origin-when-cross-origin';resp.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()';resp.headers['Content-Security-Policy']="default-src 'self' 'unsafe-inline' data: blob:; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self';";return resp
@app.get('/',response_class=HTMLResponse)
def home():return FileResponse(STATIC_DIR/'index.html')
@app.get('/admin',response_class=HTMLResponse)
def admin_page():return FileResponse(STATIC_DIR/'admin.html')
@app.get('/health')
def health():return {'ok':True,'time':now(),'db':'supabase','storage':BUCKET,'configured':bool(SUPABASE_URL and SUPABASE_KEY)}
@app.get('/robots.txt')
def robots():return Response('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/admin\nSitemap: /sitemap.xml\n',media_type='text/plain')
@app.get('/sitemap.xml')
def sitemap(req:Request):
    base=str(req.base_url).rstrip('/');return Response('<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"><url><loc>'+base+'/</loc></url></urlset>',media_type='application/xml')
def settings_dict():
    out={}
    for r in select('settings',order='key.asc'):
        try:out[r['key']]=json.loads(r['value'])
        except:out[r['key']]=r['value']
    return out
@app.get('/api/public/state')
def public_state():
    courses=select('courses',{'published':'eq.1'},'sort_order.asc,id.desc');resources=select('resources',{'published':'eq.1'});jobs=select('jobs',{'published':'eq.1'});services=select('services',{'published':'eq.1'})
    return {'settings':settings_dict(),'courses':[{'id':r['id'],'title':r['title'],'desc':r.get('description',''),'price':r.get('price',''),'status':r.get('status','')} for r in courses],'resources':[{'id':r['id'],'title':r['title'],'desc':r.get('description',''),'type':r.get('type',''),'free':bool(r.get('free')),'upload_id':r.get('upload_id')} for r in resources],'jobs':jobs,'services':services}
@app.get('/api/public/uploads')
def public_uploads():return select('uploads',{'public':'eq.1'},columns='id,title,kind,price,filename,mime,size,created_at')
class LeadIn(BaseModel):type:str;name:str;contact:str;message:str=''
@app.post('/api/leads')
def create_lead(x:LeadIn):
    if len(x.name.strip())<2 or len(x.contact.strip())<3:raise HTTPException(400,'Name and contact are required')
    r=insert('leads',{'type':x.type[:120],'name':x.name[:120],'contact':x.contact[:180],'message':x.message[:2000],'status':'New','created_at':now()});return {'ok':True,'id':r.get('id')}
class LoginIn(BaseModel):username:str;password:str
@app.post('/api/admin/login')
def login(x:LoginIn,response:Response):
    rs=select('admins',{'username':f'eq.{x.username}','active':'eq.1'},limit=1);r=rs[0] if rs else None
    if not r or not pw_verify(x.password,r['password_hash']):raise HTTPException(401,'Invalid username or password')
    response.set_cookie('hrc_session',sign_session(x.username),httponly=True,samesite='lax',secure=COOKIE_SECURE,max_age=SESSION_TTL,path='/');return {'ok':True,'username':x.username}
@app.post('/api/admin/logout')
def logout(response:Response):response.delete_cookie('hrc_session',path='/');return {'ok':True}
@app.get('/api/admin/me')
def me(req:Request):return {'username':require_admin(req)}
@app.get('/api/admin/dashboard')
def dashboard(req:Request):
    require_admin(req);return {k:count(k) for k in ['courses','resources','jobs','services','leads','uploads','drafts','sources']}
@app.get('/api/admin/settings')
def get_settings(req:Request):require_admin(req);return settings_dict()
@app.put('/api/admin/settings')
async def put_settings(req:Request):
    u=require_admin(req);payload=await req.json();allowed={'brand','community','contact','otMultiplier','eobiEmployee','eobiEmployer','pessiRate','verification','tagline','announcement','announcementActive'}
    for k,v in payload.items():
        if k not in allowed:continue
        existing=select('settings',{'key':f'eq.{k}'},order='key.asc',limit=1);d={'value':json.dumps(v),'updated_at':now()}
        if existing: sb_call('PATCH','/rest/v1/settings',{'key':f'eq.{k}'},data=d)
        else:insert('settings',{'key':k,**d})
    audit(u,'update','settings',details=','.join(payload.keys()));return {'ok':True}
TABLE_FIELDS={'courses':['title','description','price','status','published','sort_order'],'resources':['title','description','type','free','published','upload_id'],'jobs':['title','company','location','employment_type','experience','salary','description','apply_info','published'],'services':['title','description','price','published'],'sources':['title','authority','url','jurisdiction','rule_type','effective_date','verified_date','notes','active']}
def safe_table(t):
    if t not in TABLE_FIELDS:raise HTTPException(404,'Unknown collection')
    return t
@app.get('/api/admin/content/{table}')
def list_table(table:str,req:Request):require_admin(req);return select(safe_table(table))
@app.post('/api/admin/content/{table}')
async def create_table(table:str,req:Request):
    u=require_admin(req);t=safe_table(table);data=await req.json();fields=[f for f in TABLE_FIELDS[t] if f in data]
    if 'title' in TABLE_FIELDS[t] and not str(data.get('title','')).strip():raise HTTPException(400,'Title required')
    if not fields:raise HTTPException(400,'No valid fields')
    d={f:data[f] for f in fields};d.update(created_at=now(),updated_at=now());r=insert(t,d);audit(u,'create',t,r.get('id',''));return {'ok':True,'id':r.get('id')}
@app.put('/api/admin/content/{table}/{rid}')
async def update_table(table:str,rid:int,req:Request):
    u=require_admin(req);t=safe_table(table);data=await req.json();d={f:data[f] for f in TABLE_FIELDS[t] if f in data}
    if not d:raise HTTPException(400,'No valid fields')
    d['updated_at']=now();patch(t,rid,d);audit(u,'update',t,rid);return {'ok':True}
@app.delete('/api/admin/content/{table}/{rid}')
def delete_table(table:str,rid:int,req:Request):u=require_admin(req);t=safe_table(table);delete(t,rid);audit(u,'delete',t,rid);return {'ok':True}
@app.get('/api/admin/leads')
def admin_leads(req:Request):require_admin(req);return select('leads')
@app.patch('/api/admin/leads/{rid}')
async def patch_lead(rid:int,req:Request):require_admin(req);d=await req.json();patch('leads',rid,{'status':str(d.get('status','New'))[:40]});return {'ok':True}
@app.delete('/api/admin/leads/{rid}')
def del_lead(rid:int,req:Request):require_admin(req);delete('leads',rid);return {'ok':True}
@app.get('/api/admin/uploads')
def admin_uploads(req:Request):require_admin(req);return select('uploads')
@app.post('/api/admin/uploads')
async def upload_file(req:Request,file:UploadFile=File(...),title:str=Form(''),kind:str=Form('Resource'),price:str=Form('Free'),public:int=Form(1)):
    u=require_admin(req);original=clean_name(file.filename or 'file');ext=Path(original).suffix.lower()
    if ext not in ALLOWED_EXT:raise HTTPException(400,'File type not allowed')
    data=await file.read(MAX_UPLOAD+1)
    if len(data)>MAX_UPLOAD:raise HTTPException(413,f'Max upload size is {MAX_UPLOAD//1024//1024} MB')
    stored=f'{int(time.time())}_{secrets.token_hex(8)}{ext}';mime=file.content_type or mimetypes.guess_type(original)[0] or 'application/octet-stream'
    sb_call('POST',f'/storage/v1/object/{BUCKET}/{uparse.quote(stored)}',raw=data,headers={'Content-Type':mime,'x-upsert':'false'},timeout=120)
    r=insert('uploads',{'title':title.strip() or original,'kind':kind[:80],'price':price[:80],'filename':original,'stored_name':stored,'mime':mime,'size':len(data),'public':1 if public else 0,'created_at':now()});audit(u,'upload','uploads',r.get('id',''));return {'ok':True,'id':r.get('id')}
@app.delete('/api/admin/uploads/{rid}')
def delete_upload(rid:int,req:Request):
    require_admin(req);rs=select('uploads',{'id':f'eq.{rid}'},limit=1)
    if rs:
        try:sb_call('DELETE',f'/storage/v1/object/{BUCKET}',data={'prefixes':[rs[0]['stored_name']]})
        except:pass
        sb_call('PATCH','/rest/v1/resources',{'upload_id':f'eq.{rid}'},data={'upload_id':None});delete('uploads',rid)
    return {'ok':True}
@app.get('/download/{rid}')
def download(rid:int,req:Request):
    rs=select('uploads',{'id':f'eq.{rid}'},limit=1)
    if not rs:raise HTTPException(404,'File not found')
    r=rs[0]
    if not r.get('public') and not session_user(req):raise HTTPException(403,'Private file')
    data=sb_call('GET',f'/storage/v1/object/authenticated/{BUCKET}/{uparse.quote(r["stored_name"])}',timeout=120)
    return Response(content=data,media_type=r.get('mime') or 'application/octet-stream',headers={'Content-Disposition':f'attachment; filename="{clean_name(r.get("filename","download"))}"'})
class DraftIn(BaseModel):title:str;html:str
@app.get('/api/admin/drafts')
def list_drafts(req:Request):require_admin(req);return select('drafts')
@app.post('/api/admin/drafts')
def create_draft(x:DraftIn,req:Request):require_admin(req);r=insert('drafts',{'title':x.title[:180],'html':x.html,'created_at':now(),'updated_at':now()});return {'ok':True,'id':r.get('id')}
@app.delete('/api/admin/drafts/{rid}')
def del_draft(rid:int,req:Request):require_admin(req);delete('drafts',rid);return {'ok':True}
class PasswordIn(BaseModel):current_password:str;new_password:str
@app.post('/api/admin/change-password')
def change_password(x:PasswordIn,req:Request):
    u=require_admin(req)
    if len(x.new_password)<12:raise HTTPException(400,'New password must be at least 12 characters')
    rs=select('admins',{'username':f'eq.{u}'},limit=1);r=rs[0] if rs else None
    if not r or not pw_verify(x.current_password,r['password_hash']):raise HTTPException(400,'Current password is incorrect')
    sb_call('PATCH','/rest/v1/admins',{'username':f'eq.{u}'},data={'password_hash':pw_hash(x.new_password)});return {'ok':True}
if __name__=='__main__':
    import uvicorn;uvicorn.run('app:app',host=os.getenv('HOST','127.0.0.1'),port=int(os.getenv('PORT','8000')),reload=False)
