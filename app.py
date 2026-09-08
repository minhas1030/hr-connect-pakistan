from __future__ import annotations
import os, json, secrets, hashlib, hmac, base64, mimetypes, re, time, html
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

app=FastAPI(title='HR Connect Pakistan',version='6.0.0')
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
    defaults={'brand':'HR Connect Pakistan','community':'','contact':'','otMultiplier':2.0,'eobiEmployee':0,'eobiEmployer':0,'pessiRate':0,'verification':'Not configured','tagline':'Practical HR Tools, Resources & Career Solutions','announcement':'','announcementActive':False,'certificateIssuer':'Awais Minhas','certificateRole':'Founder / HR Professional','certificatePrefix':'HRC','certificateHoursDefault':2,'supportWhatsapp':'','ga4Id':'','adsenseClient':'','searchConsoleVerification':'','siteAuthor':'Awais Minhas','siteAuthorRole':'HR Professional | Trainer | Consultant'}
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
    resp=await call_next(req); resp.headers['X-Content-Type-Options']='nosniff';resp.headers['X-Frame-Options']='SAMEORIGIN';resp.headers['Referrer-Policy']='strict-origin-when-cross-origin';resp.headers['Permissions-Policy']='camera=(), microphone=(), geolocation=()';resp.headers['Content-Security-Policy']="default-src 'self' data: blob:; script-src 'self' 'unsafe-inline' https://www.googletagmanager.com https://pagead2.googlesyndication.com; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob: https:; media-src 'self' blob:; connect-src 'self' https://www.google-analytics.com https://region1.google-analytics.com; frame-src https://googleads.g.doubleclick.net https://tpc.googlesyndication.com;";return resp
TOOL_SEO={
'ats-resume-checker':('ATS Resume Checker Pakistan | HR Connect Pakistan','Compare a resume with a target job description, identify keyword gaps and generate a practical ATS relevance report.'),
'resume-summary-builder':('Professional Resume Summary Builder Pakistan','Create a stronger professional resume summary using role, experience, skills and measurable achievements.'),
'employee-turnover-calculator':('Employee Turnover Calculator | HR Metric Tool','Calculate employee turnover rate and generate a printable HR metric report.'),
'absenteeism-calculator':('Absenteeism Rate Calculator | HR Connect Pakistan','Calculate absenteeism rate from scheduled workdays and absent days for HR reporting.'),
'attendance-percentage-calculator':('Attendance Percentage Calculator | HR Tool Pakistan','Calculate attendance percentage quickly for HR reporting and workforce analysis.'),
'cost-per-hire-calculator':('Cost Per Hire Calculator | Recruitment KPI','Calculate recruitment cost per hire using internal and external hiring costs.'),
'time-to-hire-calculator':('Time to Hire Calculator | Recruitment KPI','Measure average days from requisition or candidate entry to accepted offer.'),
'overtime-calculator-pakistan':('Overtime Calculator Pakistan | Double Rate HR Tool','Estimate overtime pay in Pakistan using configurable rates and a transparent calculation report.'),
'eobi-calculator-pakistan':('EOBI Contribution Calculator Pakistan | HR Connect Pakistan','Estimate employee and employer EOBI contributions using configurable statutory percentages.'),
'social-security-calculator-punjab':('PESSI Social Security Calculator Punjab Pakistan','Estimate Punjab employer social security contribution using configurable PESSI settings.'),
'salary-tax-calculator-pakistan':('Pakistan Salary Tax Calculator 2026–27 | FBR Slabs','Estimate monthly and annual salary income tax and take-home pay using Pakistan FY 2026–27 salaried-person slabs under Finance Act 2026.'),
'gross-to-net-salary-calculator-pakistan':('Gross to Net Salary Calculator Pakistan 2026–27','Estimate monthly take-home salary after FY 2026–27 salary tax and optional payroll deductions.'),
'job-offer-comparison-pakistan':('Job Offer Comparison Calculator Pakistan','Compare two job offers by salary, benefits and recurring commute costs before making a career decision.'),
'salary-slip-generator-pakistan':('Free Salary Slip Generator Pakistan | HR Connect Pakistan','Create a clean printable salary slip with earnings, deductions and net pay.'),
'gratuity-calculator-pakistan':('Gratuity Calculator Pakistan | HR Connect Pakistan','Create an educational gratuity estimate from salary and qualifying service inputs.'),
'leave-encashment-calculator':('Leave Encashment Calculator Pakistan | HR Tool','Estimate the monetary value of eligible unused leave using salary and leave-day inputs.'),
'full-and-final-settlement-calculator':('Full and Final Settlement Calculator Pakistan','Estimate salary dues, leave encashment, additions and deductions for employee final settlement.'),
'notice-period-calculator':('Notice Period Calculator Pakistan | Last Working Day','Calculate an expected last working date from notice date and notice period.'),
'probation-end-date-calculator':('Probation End Date Calculator | HR Connect Pakistan','Calculate expected probation completion date from joining date and probation duration.'),
'increment-calculator':('Salary Increment Calculator Pakistan | HR Tool','Calculate salary increase amount and percentage from current and revised salary.'),
'show-cause-notice-generator':('Show Cause Notice Generator Pakistan | HR Document','Create a neutral, letterhead-safe show-cause notice draft with response deadline and signature areas.'),
'job-description-generator':('Job Description Generator Pakistan | HR Connect Pakistan','Create a professional job description with purpose, responsibilities, KPIs, qualifications and reporting line.'),
'hr-document-studio':('Free HR Document Templates Pakistan | HR Connect Pakistan','Create professional HR letters and workplace documents for pre-printed company letterhead.')}

def _inject_meta(text,title,description,canonical,lang='en',schema=None):
    title=html.escape(title,quote=True); description=html.escape(description,quote=True); canonical=html.escape(canonical,quote=True)
    text=re.sub(r'<title>.*?</title>',f'<title>{title}</title>',text,count=1,flags=re.S)
    text=re.sub(r'<meta name="description" content="[^"]*">',f'<meta name="description" content="{description}">',text,count=1)
    text=re.sub(r'<link rel="canonical" href="[^"]*">',f'<link rel="canonical" href="{canonical}">',text,count=1)
    text=re.sub(r'<meta property="og:title" content="[^"]*">',f'<meta property="og:title" content="{title}">',text,count=1)
    text=re.sub(r'<meta property="og:description" content="[^"]*">',f'<meta property="og:description" content="{description}">',text,count=1)
    text=re.sub(r'<meta property="og:url" content="[^"]*">',f'<meta property="og:url" content="{canonical}">',text,count=1)
    if lang=='ur':
        text=text.replace('<html lang="en">','<html lang="ur" dir="rtl">',1)
        text=text.replace('<script>','<script>window.__DEFAULT_LANG__="ur";\n',1)
    if schema:
        text=text.replace('</head>',f'<script type="application/ld+json">{json.dumps(schema,ensure_ascii=False)}</script></head>',1)
    return text

def serve_index(title='HR Connect Pakistan — Practical HR Tools, Documents, Jobs & Career Resources',description='HR Connect Pakistan provides practical HR calculators, ATS resume matching, printable HR documents, job descriptions, show-cause notices, HR resources, jobs, training and recruitment support for Pakistan.',canonical='https://hr-connect-pakistan-live.onrender.com/',lang='en',schema=None):
    text=(STATIC_DIR/'index.html').read_text(encoding='utf-8')
    try: token=str(settings_dict().get('searchConsoleVerification','') or '')
    except: token=''
    text=text.replace('__GSC_VERIFICATION__',token)
    return HTMLResponse(_inject_meta(text,title,description,canonical,lang,schema))
@app.get('/',response_class=HTMLResponse)
def home(req:Request):
    base=str(req.base_url).rstrip('/')
    return serve_index(canonical=base+'/',schema={'@context':'https://schema.org','@type':'WebSite','name':'HR Connect Pakistan','url':base+'/'})
@app.get('/ur',response_class=HTMLResponse)
def ur_home(req:Request):
    base=str(req.base_url).rstrip('/')
    return serve_index('HR Connect Pakistan — پاکستان کے لیے عملی HR ٹولز','پاکستان کے HR پروفیشنلز کے لیے مفت HR ٹولز، کیلکولیٹرز، دستاویزات، کورسز، سرٹیفکیٹ ویریفیکیشن اور عملی وسائل۔',base+'/ur','ur',{'@context':'https://schema.org','@type':'WebSite','name':'HR Connect Pakistan Urdu','url':base+'/ur','inLanguage':'ur-PK'})
@app.get('/admin',response_class=HTMLResponse)
def admin_page():return FileResponse(STATIC_DIR/'admin.html')
@app.head('/')
def head_home():return Response(status_code=200)
@app.get('/health')
def health():return {'ok':True,'time':now(),'db':'supabase','storage':BUCKET,'configured':bool(SUPABASE_URL and SUPABASE_KEY),'version':'5.0.0'}
@app.get('/robots.txt')
def robots():return Response('User-agent: *\nAllow: /\nDisallow: /admin\nDisallow: /api/admin\nSitemap: /sitemap.xml\n',media_type='text/plain')
SEO_SLUGS=['ats-resume-checker','resume-summary-builder','employee-turnover-calculator','absenteeism-calculator','attendance-percentage-calculator','cost-per-hire-calculator','time-to-hire-calculator','overtime-calculator-pakistan','eobi-calculator-pakistan','social-security-calculator-punjab','salary-tax-calculator-pakistan','gross-to-net-salary-calculator-pakistan','job-offer-comparison-pakistan','salary-slip-generator-pakistan','gratuity-calculator-pakistan','leave-encashment-calculator','full-and-final-settlement-calculator','notice-period-calculator','probation-end-date-calculator','increment-calculator','show-cause-notice-generator','job-description-generator','hr-document-studio']
@app.get('/sitemap.xml')
def sitemap(req:Request):
    base=str(req.base_url).rstrip('/'); article_urls=[]; job_urls=[]
    try: job_urls=[f"{base}/jobs/{r['slug']}" for r in select('jobs',{'published':'eq.1','slug':'not.is.null'},columns='slug') if r.get('slug')]
    except: pass
    try: article_urls=[f"{base}/learn/{r['slug']}" for r in select('articles',{'published':'eq.1'},columns='slug')]
    except: pass
    urls=[base+'/',base+'/ur']+[f'{base}/tools/{x}' for x in SEO_SLUGS]+[f'{base}/ur/tools/{x}' for x in SEO_SLUGS]+[base+'/certificate/verify',base+'/about',base+'/privacy',base+'/terms']+article_urls+[u.replace('/learn/','/ur/learn/') for u in article_urls]+job_urls
    body='<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'+''.join(f'<url><loc>{u}</loc><changefreq>weekly</changefreq></url>' for u in urls)+'</urlset>'
    return Response(body,media_type='application/xml')
@app.get('/tools/{slug}',response_class=HTMLResponse)
def seo_tool_page(slug:str,req:Request):
    if slug not in SEO_SLUGS: raise HTTPException(404,'Tool not found')
    base=str(req.base_url).rstrip('/'); title,desc=TOOL_SEO.get(slug,('HR Tool | HR Connect Pakistan','Practical HR tool for Pakistan.'))
    schema={'@context':'https://schema.org','@type':'WebApplication','name':title.split('|')[0].strip(),'applicationCategory':'BusinessApplication','operatingSystem':'Web','isAccessibleForFree':True,'url':base+f'/tools/{slug}','description':desc}
    return serve_index(title,desc,base+f'/tools/{slug}','en',schema)
@app.get('/ur/tools/{slug}',response_class=HTMLResponse)
def ur_tool_page(slug:str,req:Request):
    if slug not in SEO_SLUGS: raise HTTPException(404,'Tool not found')
    base=str(req.base_url).rstrip('/'); title,desc=TOOL_SEO.get(slug,('HR Tool | HR Connect Pakistan','Practical HR tool for Pakistan.'))
    return serve_index(title+' — اردو',desc+' اردو انٹرفیس کے ساتھ۔',base+f'/ur/tools/{slug}','ur',{'@context':'https://schema.org','@type':'WebApplication','name':title.split('|')[0].strip(),'inLanguage':'ur-PK','url':base+f'/ur/tools/{slug}'})
@app.get('/manifest.webmanifest')
def manifest(req:Request):
    data={'name':'HR Connect Pakistan','short_name':'HR Connect','description':'Practical HR tools, documents, learning and resources for Pakistan.','start_url':'/','scope':'/','display':'standalone','background_color':'#05080c','theme_color':'#07110f','lang':'en-PK','icons':[],'shortcuts':[{'name':'HR Tools','url':'/#tools'},{'name':'Verify Certificate','url':'/certificate/verify'},{'name':'Urdu','url':'/ur'}]}
    return Response(json.dumps(data,ensure_ascii=False),media_type='application/manifest+json')
@app.get('/sw.js')
def service_worker():
    js="const CACHE='hrc-v6';const CORE=['/','/ur','/manifest.webmanifest'];self.addEventListener('install',e=>e.waitUntil(caches.open(CACHE).then(c=>c.addAll(CORE))));self.addEventListener('activate',e=>e.waitUntil(caches.keys().then(k=>Promise.all(k.filter(x=>x!==CACHE).map(x=>caches.delete(x))))));self.addEventListener('fetch',e=>{if(e.request.method!=='GET')return;e.respondWith(fetch(e.request).then(r=>{let x=r.clone();caches.open(CACHE).then(c=>c.put(e.request,x));return r}).catch(()=>caches.match(e.request).then(r=>r||caches.match('/'))))});"
    return Response(js,media_type='application/javascript',headers={'Service-Worker-Allowed':'/'})
@app.get('/feed.xml')
def rss_feed(req:Request):
    base=str(req.base_url).rstrip('/'); items=[]
    try: rows=select('articles',{'published':'eq.1'},'published_at.desc,id.desc',limit=30)
    except: rows=[]
    for a in rows:
        title=html.escape(a.get('title','')); link=f"{base}/learn/{a.get('slug','')}"; desc=html.escape(a.get('excerpt','')); date=html.escape(a.get('published_at',''))
        items.append(f'<item><title>{title}</title><link>{link}</link><guid>{link}</guid><description>{desc}</description><pubDate>{date}</pubDate></item>')
    xml='<?xml version="1.0" encoding="UTF-8"?><rss version="2.0"><channel><title>HR Connect Pakistan</title><link>'+base+'</link><description>Practical HR tools, guides and updates for Pakistan.</description>'+''.join(items)+'</channel></rss>'
    return Response(xml,media_type='application/rss+xml')
@app.get('/ads.txt')
def ads_txt():
    try: cid=str(settings_dict().get('adsenseClient','') or '').strip()
    except: cid=''
    m=re.search(r'(?:ca-)?(pub-\d+)',cid)
    if not m:return Response('# AdSense publisher ID not configured yet.\n',media_type='text/plain')
    return Response(f'google.com, {m.group(1)}, DIRECT, f08c47fec0942fa0\n',media_type='text/plain')
@app.get('/llms.txt')
def llms_txt(req:Request):
    base=str(req.base_url).rstrip('/')
    body='# HR Connect Pakistan\n\nPractical HR tools, document generators, training, certificate verification, jobs and Pakistan-focused HR learning resources.\n\n## Important URLs\n- '+base+'/\n- '+base+'/ur\n- '+base+'/sitemap.xml\n- '+base+'/feed.xml\n- '+base+'/certificate/verify\n\nStatutory calculators are configurable educational/operational aids and must be checked against current applicable law and official notifications.\n'
    return Response(body,media_type='text/plain')
@app.get('/certificate/verify',response_class=HTMLResponse)
def certificate_verify_page():return serve_index()
@app.get('/about',response_class=HTMLResponse)
def about_page():return serve_index()
@app.get('/privacy',response_class=HTMLResponse)
def privacy_page():return serve_index()
@app.get('/terms',response_class=HTMLResponse)
def terms_page():return serve_index()
@app.get('/learn/{slug}',response_class=HTMLResponse)
def learn_page(slug:str,req:Request):
    rs=select('articles',{'slug':f'eq.{slug}','published':'eq.1'},limit=1)
    if not rs: raise HTTPException(404,'Article not found')
    a=rs[0]; base=str(req.base_url).rstrip('/'); title=a.get('meta_title') or a.get('title') or 'HR Knowledge | HR Connect Pakistan'; desc=a.get('meta_description') or a.get('excerpt') or 'Practical HR guidance for Pakistan.'
    schema={'@context':'https://schema.org','@type':'Article','headline':a.get('title',''),'description':desc,'author':{'@type':'Person','name':a.get('author','Awais Minhas')},'publisher':{'@type':'Organization','name':'HR Connect Pakistan'},'datePublished':a.get('published_at',''),'mainEntityOfPage':base+f'/learn/{slug}'}
    return serve_index(title,desc,base+f'/learn/{slug}','en',schema)
@app.get('/ur/learn/{slug}',response_class=HTMLResponse)
def ur_learn_page(slug:str,req:Request):
    rs=select('articles',{'slug':f'eq.{slug}','published':'eq.1'},limit=1)
    if not rs: raise HTTPException(404,'Article not found')
    a=rs[0]; base=str(req.base_url).rstrip('/'); title=(a.get('meta_title') or a.get('title') or 'HR Knowledge')+' — اردو'; desc=a.get('meta_description') or a.get('excerpt') or 'Practical HR guidance for Pakistan.'
    return serve_index(title,desc+' اردو انٹرفیس کے ساتھ۔',base+f'/ur/learn/{slug}','ur',{'@context':'https://schema.org','@type':'Article','headline':a.get('title',''),'inLanguage':'ur-PK','mainEntityOfPage':base+f'/ur/learn/{slug}'})
def settings_dict():
    out={}
    for r in select('settings',order='key.asc'):
        try:out[r['key']]=json.loads(r['value'])
        except:out[r['key']]=r['value']
    return out
@app.get('/jobs/{slug}',response_class=HTMLResponse)
def public_job_page(slug:str,req:Request):
    rs=select('jobs',{'slug':f'eq.{slug}','published':'eq.1'},limit=1)
    if not rs: raise HTTPException(404,'Job not found')
    j=rs[0]; base=str(req.base_url).rstrip('/'); title=f"{j.get('title','Job')} — {j.get('company','')} | HR Connect Pakistan"; desc=(j.get('description') or '')[:155] or f"Verified job opportunity in {j.get('location','Pakistan')}"
    schema={'@context':'https://schema.org','@type':'JobPosting','title':j.get('title',''),'description':j.get('description',''),'datePosted':j.get('date_posted') or j.get('created_at','')[:10],'hiringOrganization':{'@type':'Organization','name':j.get('company','')},'jobLocation':{'@type':'Place','address':{'@type':'PostalAddress','addressLocality':j.get('location',''),'addressCountry':'PK'}}}
    if j.get('valid_through'): schema['validThrough']=j['valid_through']
    if j.get('employment_type'): schema['employmentType']=j['employment_type']
    return serve_index(title,desc,base+f'/jobs/{slug}','en',schema)

@app.get('/api/public/state')
def public_state():
    courses=select('courses',{'published':'eq.1'},'sort_order.asc,id.desc');resources=select('resources',{'published':'eq.1'});jobs=select('jobs',{'published':'eq.1'});services=select('services',{'published':'eq.1'})
    sources=select('sources',{'active':'eq.1'},'id.asc')
    cert_count=count('certificates')
    articles=select('articles',{'published':'eq.1'},'featured.desc,published_at.desc,id.desc',limit=12)
    return {'settings':settings_dict(),'courses':[{'id':r['id'],'title':r['title'],'title_ur':r.get('title_ur',''),'desc':r.get('description',''),'description_ur':r.get('description_ur',''),'price':r.get('price',''),'status':r.get('status',''),'certificate_enabled':bool(r.get('certificate_enabled',1)),'learning_hours':r.get('learning_hours',0),'enrollment_open':bool(r.get('enrollment_open',0)),'price_amount':float(r.get('price_amount') or 0),'currency':r.get('currency','PKR')} for r in courses],'resources':[{'id':r['id'],'title':r['title'],'title_ur':r.get('title_ur',''),'desc':r.get('description',''),'description_ur':r.get('description_ur',''),'type':r.get('type',''),'free':bool(r.get('free')),'upload_id':r.get('upload_id')} for r in resources],'jobs':jobs,'services':services,'sources':sources,'articles':[{'id':r['id'],'title':r['title'],'title_ur':r.get('title_ur',''),'slug':r['slug'],'excerpt':r.get('excerpt',''),'excerpt_ur':r.get('excerpt_ur',''),'category':r.get('category','HR Knowledge'),'author':r.get('author','Awais Minhas'),'published_at':r.get('published_at','')} for r in articles],'stats':{'certificates_issued':cert_count}}
@app.get('/api/public/course/{course_id}')
def public_course(course_id:int):
    rs=select('courses',{'id':f'eq.{course_id}','published':'eq.1'},limit=1)
    if not rs: raise HTTPException(404,'Course not found')
    c=rs[0]; mods=select('course_modules',{'course_id':f'eq.{course_id}','published':'eq.1'},'sort_order.asc,id.asc')
    safe=[]
    for m in mods:
        safe.append({'id':m['id'],'title':m['title'],'description':m.get('description',''),'sort_order':m.get('sort_order',0),'duration_minutes':m.get('duration_minutes',0),'module_type':m.get('module_type','Lesson'),'content_url':m.get('content_url',''),'upload_id':m.get('upload_id'),'required':bool(m.get('required',1))})
    return {'course':{'id':c['id'],'title':c['title'],'title_ur':c.get('title_ur',''),'description':c.get('description',''),'description_ur':c.get('description_ur',''),'price':c.get('price',''),'status':c.get('status',''),'certificate_enabled':bool(c.get('certificate_enabled',1)),'learning_hours':c.get('learning_hours',0),'enrollment_open':bool(c.get('enrollment_open',0)),'price_amount':float(c.get('price_amount') or 0),'currency':c.get('currency','PKR'),'payment_url':c.get('payment_url',''),'payment_instructions':c.get('payment_instructions','')},'modules':safe}

class SubscribeIn(BaseModel):email:str
@app.post('/api/public/subscribe')
def subscribe(x:SubscribeIn):
    email=x.email.strip().lower()
    if not re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$',email): raise HTTPException(400,'Enter a valid email address')
    if select('subscribers',{'email':f'eq.{email}'},limit=1): return {'ok':True,'message':'You are already subscribed.'}
    insert('subscribers',{'email':email[:180],'source':'website','active':1,'created_at':now()})
    return {'ok':True,'message':'Subscribed successfully.'}

@app.get('/api/public/article/{slug}')
def public_article(slug:str):
    rs=select('articles',{'slug':f'eq.{slug}','published':'eq.1'},limit=1)
    if not rs: raise HTTPException(404,'Article not found')
    return rs[0]

class EnrollmentIn(BaseModel):
    course_id:int
    full_name:str
    email:str
    phone:str=''
@app.post('/api/public/enroll')
def public_enroll(x:EnrollmentIn):
    rs=select('courses',{'id':f'eq.{x.course_id}','published':'eq.1'},limit=1)
    if not rs or not bool(rs[0].get('enrollment_open',0)): raise HTTPException(400,'Enrollment is not currently open for this course')
    name=x.full_name.strip(); email=x.email.strip().lower()
    if len(name)<2 or '@' not in email: raise HTTPException(400,'Valid name and email are required')
    existing=select('enrollments',{'course_id':f'eq.{x.course_id}','email':f'eq.{email}'},limit=1)
    if existing:return {'ok':True,'id':existing[0]['id'],'message':'Already enrolled'}
    r=insert('enrollments',{'course_id':x.course_id,'full_name':name[:160],'email':email[:180],'phone':x.phone.strip()[:80],'status':'Enrolled','progress':0,'created_at':now(),'updated_at':now()})
    return {'ok':True,'id':r.get('id'),'message':'Enrollment received'}

@app.get('/api/public/uploads')
def public_uploads():return select('uploads',{'public':'eq.1'},columns='id,title,kind,price,filename,mime,size,created_at')
class LeadIn(BaseModel):type:str;name:str;contact:str;message:str=''
@app.post('/api/leads')
def create_lead(x:LeadIn):
    if len(x.name.strip())<2 or len(x.contact.strip())<3:raise HTTPException(400,'Name and contact are required')
    r=insert('leads',{'type':x.type[:120],'name':x.name[:120],'contact':x.contact[:180],'message':x.message[:2000],'status':'New','created_at':now()});return {'ok':True,'id':r.get('id')}
@app.get('/api/public/certificate/{code}')
def verify_certificate(code:str):
    code=(code or '').strip()[:100]
    if not code: raise HTTPException(400,'Certificate code is required')
    rows=sb_call('POST','/rest/v1/rpc/verify_hrc_certificate',data={'code':code}) or []
    if not rows: raise HTTPException(404,'Certificate not found')
    return {'valid':str(rows[0].get('status','')).lower()=='valid','certificate':rows[0]}

class UsageIn(BaseModel):
    tool_key:str
    event_type:str='open'
@app.post('/api/public/tool-usage')
def tool_usage(x:UsageIn):
    key=re.sub(r'[^a-z0-9_-]','',x.tool_key.lower())[:80]
    event=re.sub(r'[^a-z0-9_-]','',x.event_type.lower())[:30] or 'open'
    if key: insert('tool_usage',{'tool_key':key,'event_type':event,'created_at':now()})
    return {'ok':True}

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
    require_admin(req);return {k:count(k) for k in ['courses','resources','jobs','services','leads','uploads','drafts','sources','enrollments','certificates','course_modules','tool_usage','articles','subscribers']}
@app.get('/api/admin/settings')
def get_settings(req:Request):require_admin(req);return settings_dict()
@app.put('/api/admin/settings')
async def put_settings(req:Request):
    u=require_admin(req);payload=await req.json();allowed={'brand','community','contact','otMultiplier','eobiEmployee','eobiEmployer','pessiRate','verification','tagline','announcement','announcementActive','certificateIssuer','certificateRole','certificatePrefix','certificateHoursDefault','supportWhatsapp','ga4Id','adsenseClient','searchConsoleVerification','siteAuthor','siteAuthorRole'}
    for k,v in payload.items():
        if k not in allowed:continue
        existing=select('settings',{'key':f'eq.{k}'},order='key.asc',limit=1);d={'value':json.dumps(v),'updated_at':now()}
        if existing: sb_call('PATCH','/rest/v1/settings',{'key':f'eq.{k}'},data=d)
        else:insert('settings',{'key':k,**d})
    audit(u,'update','settings',details=','.join(payload.keys()));return {'ok':True}
TABLE_FIELDS={'courses':['title','title_ur','description','description_ur','price','status','published','sort_order','certificate_enabled','learning_hours','enrollment_open','price_amount','currency','payment_url','payment_instructions'],'course_modules':['course_id','title','description','sort_order','duration_minutes','published','module_type','content_url','upload_id','required'],'resources':['title','title_ur','description','description_ur','type','free','published','upload_id'],'jobs':['title','title_ur','company','location','employment_type','experience','salary','description','description_ur','apply_info','apply_info_ur','published'],'services':['title','title_ur','description','description_ur','price','published'],'sources':['title','authority','url','jurisdiction','rule_type','effective_date','verified_date','notes','active'],'enrollments':['course_id','full_name','email','phone','status','progress','completed_at'],'articles':['title','title_ur','slug','excerpt','excerpt_ur','body','body_ur','category','meta_title','meta_title_ur','meta_description','meta_description_ur','author','published','featured','published_at']}
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
class CertificateIn(BaseModel):
    participant_name:str
    participant_email:str=''
    course_id:Optional[int]=None
    course_title:str=''
    completion_date:str=''
    learning_hours:float=0
    issuer_name:str=''
    notes:str=''

def certificate_codes(prefix='HRC'):
    year=datetime.now(timezone.utc).year
    for _ in range(8):
        token=secrets.token_hex(4).upper()
        no=f'{prefix}-{year}-{token[:6]}'
        verify=f'{prefix}-{token[:4]}-{token[4:8]}'
        if not select('certificates',{'certificate_no':f'eq.{no}'},limit=1) and not select('certificates',{'verification_code':f'eq.{verify}'},limit=1): return no,verify
    raise HTTPException(500,'Could not generate certificate code')

@app.get('/api/admin/certificates')
def admin_certificates(req:Request):require_admin(req);return select('certificates')
@app.post('/api/admin/certificates')
def issue_certificate(x:CertificateIn,req:Request):
    u=require_admin(req); st=settings_dict(); name=x.participant_name.strip()
    if len(name)<2: raise HTTPException(400,'Participant name is required')
    ctitle=x.course_title.strip()
    if x.course_id:
        rs=select('courses',{'id':f'eq.{x.course_id}'},limit=1)
        if rs and not ctitle: ctitle=rs[0].get('title','')
    if not ctitle: raise HTTPException(400,'Course title is required')
    prefix=re.sub(r'[^A-Za-z0-9]','',str(st.get('certificatePrefix','HRC')))[:10] or 'HRC'
    no,verify=certificate_codes(prefix.upper())
    hours=x.learning_hours if x.learning_hours>0 else float(st.get('certificateHoursDefault',2) or 0)
    d={'certificate_no':no,'verification_code':verify,'course_id':x.course_id,'participant_name':name,'participant_email':x.participant_email.strip()[:180],'course_title':ctitle,'completion_date':x.completion_date or datetime.now(timezone.utc).date().isoformat(),'issued_at':now(),'learning_hours':hours,'status':'Valid','issuer_name':x.issuer_name.strip() or str(st.get('certificateIssuer','Awais Minhas')),'notes':x.notes[:1000],'created_at':now(),'updated_at':now()}
    r=insert('certificates',d); audit(u,'issue','certificates',r.get('id',''),no); return {'ok':True,'id':r.get('id'),'certificate_no':no,'verification_code':verify}
@app.patch('/api/admin/certificates/{rid}')
async def update_certificate(rid:int,req:Request):
    u=require_admin(req); d=await req.json(); allowed={'participant_name','participant_email','course_title','completion_date','learning_hours','status','issuer_name','notes'}; payload={k:d[k] for k in allowed if k in d}; payload['updated_at']=now(); patch('certificates',rid,payload); audit(u,'update','certificates',rid); return {'ok':True}
@app.delete('/api/admin/certificates/{rid}')
def delete_certificate(rid:int,req:Request):u=require_admin(req);delete('certificates',rid);audit(u,'delete','certificates',rid);return {'ok':True}

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
