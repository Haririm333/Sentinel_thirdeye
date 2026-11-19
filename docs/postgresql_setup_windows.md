# PostgreSQL Setup Guide for Windows 11

This guide documents how PostgreSQL is configured for SENTINEL on a Windows 11 workstation.

## Option A: Automated Portable Setup (Recommended for Local Dev & Testing)
SENTINEL includes an automated setup script that downloads official PostgreSQL 16 x64 binaries, initializes the data directory, configures the database user and password, and launches the server in user-space without requiring administrative / UAC elevation.

### Step 1: Run the setup script in PowerShell
```powershell
python sentinel\setup_portable_postgres.py
```
This script:
1. Downloads `postgresql-16.2-1-windows-x64-binaries.zip` from EnterpriseDB.
2. Extracts binaries into `sentinel\pgsql_dist`.
3. Initializes a fresh UTF-8 database cluster in `sentinel\pgsql_data`.
4. Starts the server bound to `127.0.0.1:5432`.
5. Creates the `sentinel_user` role with password `sentinel_secure_pass`.
6. Creates the `sentinel_db` database owned by `sentinel_user`.

### Step 2: Start / Stop Commands
To start PostgreSQL manually:
```powershell
sentinel\pgsql_dist\pgsql\bin\pg_ctl.exe -D "E:\project crimathon\drive-download-20261119T081747Z-1-001\pipeline buid\sentinel\pgsql_data" -l sentinel\pgsql.log -o "-h 127.0.0.1 -p 5432" start
```
To check status:
```powershell
sentinel\pgsql_dist\pgsql\bin\pg_ctl.exe -D "E:\project crimathon\drive-download-20261119T081747Z-1-001\pipeline buid\sentinel\pgsql_data" status
```
To stop the server:
```powershell
sentinel\pgsql_dist\pgsql\bin\pg_ctl.exe -D "E:\project crimathon\drive-download-20261119T081747Z-1-001\pipeline buid\sentinel\pgsql_data" stop
```

---

## Option B: Standard Windows PostgreSQL Service Installation (via winget or MSI)

If you prefer installing PostgreSQL as a Windows system service:

### Step 1: Install using winget (requires Administrator terminal)
```powershell
winget install --id PostgreSQL.PostgreSQL.16 --accept-package-agreements --accept-source-agreements
```

### Step 2: Add psql to your PATH
Add `C:\Program Files\PostgreSQL\16\bin` to your System Environment `PATH`.

### Step 3: Create User and Database via psql
Open PowerShell and connect as the superuser:
```powershell
psql -U postgres -h 127.0.0.1 -p 5432
```
Execute SQL statements:
```sql
CREATE ROLE sentinel_user WITH LOGIN PASSWORD 'sentinel_secure_pass';
CREATE DATABASE sentinel_db OWNER sentinel_user;
GRANT ALL PRIVILEGES ON DATABASE sentinel_db TO sentinel_user;
```

---

## Option C: Offline SQLite Mode (Zero External Dependencies)
For offline local development or running tests without a database server running:
Update `sentinel\backend\.env`:
```ini
DATABASE_URL=sqlite:///./sentinel_local.db
```
SQLAlchemy handles SQLite transparently with full schema compatibility.
