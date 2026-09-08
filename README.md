# HR Connect Pakistan — Full-Stack Final Build

This package converts the premium HR Connect Pakistan frontend into a real server-backed application.

## Included

- FastAPI backend
- SQLite database with WAL mode
- Secure hashed admin password (scrypt)
- Signed HttpOnly admin session cookie
- Server-side settings and calculator configuration
- Courses CRUD
- Resources CRUD
- Jobs CRUD
- Services CRUD
- Source registry for statutory/rule verification
- Lead capture + lead status pipeline
- Real server-side uploads and downloads
- Public/private upload access
- Admin password change
- Audit log table
- Health endpoint
- Security headers
- File type and upload-size validation
- Dockerfile
- Windows and Linux/macOS start scripts
- Database/upload backup script

## Local launch (Windows)

1. Install Python 3.11+.
2. Extract the ZIP.
3. Open the folder and run `run_local.bat`.
4. Open `http://127.0.0.1:8000`.
5. Open `http://127.0.0.1:8000/admin`.

First local admin credentials:

- Username: `admin`
- Password: `ChangeThisBeforeDeploy!`

Change the password immediately from Admin → Security.

## Before public deployment

Create environment variables based on `.env.example`:

- `APP_SECRET`: long random secret
- `ADMIN_USERNAME`: your admin username
- `ADMIN_PASSWORD`: strong first-run password for a new database
- `COOKIE_SECURE=1` when HTTPS is enabled
- `DATA_DIR`, `UPLOAD_DIR`, `DB_PATH`: point these to persistent storage on the host

Never deploy with the default password or development secret.

## Persistent hosting requirement

SQLite and uploaded files must live on persistent disk/storage. If a host wipes its filesystem on redeploy, configure a persistent mounted volume or migrate the storage layer to a managed database/object storage provider.

## Backup

Run:

`python backup.py`

This creates a database backup and ZIP of uploaded files in `/backups`.

## Calculator/statutory rules

No unverified Pakistan statutory rate is hard-coded. Use Admin → Site Settings and Admin → Rule Sources to enter verified current values, effective dates and official source references.

## Future extensions

The backend is deliberately modular. You can later add AI APIs, payment gateways, email providers, student accounts, employer accounts, subscriptions and managed Postgres/object storage without rebuilding the public frontend.
