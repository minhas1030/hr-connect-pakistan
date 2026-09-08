from pathlib import Path
from datetime import datetime
import shutil, sqlite3, os
BASE=Path(__file__).resolve().parent
src=Path(os.getenv('DB_PATH',BASE/'data'/'hrconnect.db'))
out=BASE/'backups';out.mkdir(exist_ok=True)
stamp=datetime.now().strftime('%Y%m%d_%H%M%S')
dst=out/f'hrconnect_{stamp}.db'
with sqlite3.connect(src) as s, sqlite3.connect(dst) as d:s.backup(d)
uploads=Path(os.getenv('UPLOAD_DIR',BASE/'uploads'))
if uploads.exists():shutil.make_archive(str(out/f'uploads_{stamp}'),'zip',uploads)
print('Backup created:',dst)
