"""
Portable PostgreSQL 16 Setup for SENTINEL Local Development (Windows 11)
Downloads EnterpriseDB Windows x64 binaries, initializes data directory,
creates sentinel_user with password 'sentinel_secure_pass' and database 'sentinel_db',
and starts the PostgreSQL server on 127.0.0.1:5432.
"""

import os
import sys
import time
import zipfile
import subprocess
import urllib.request
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
PG_ROOT = BASE_DIR / "pgsql_dist"
ZIP_PATH = BASE_DIR / "postgresql-binaries.zip"
DATA_DIR = BASE_DIR / "pgsql_data"
LOG_FILE = BASE_DIR / "pgsql.log"

DOWNLOAD_URL = "https://get.enterprisedb.com/postgresql/postgresql-16.2-1-windows-x64-binaries.zip"

def download_file(url: str, dest: Path):
    if dest.exists() and dest.stat().st_size > 300_000_000:
        print(f"Archive already exists at {dest} ({dest.stat().st_size} bytes). Skipping download.")
        return
    print(f"Downloading PostgreSQL binaries from {url} to {dest}...")
    def reporthook(blocknum, blocksize, totalsize):
        readsofar = blocknum * blocksize
        if totalsize > 0 and blocknum % 500 == 0:
            percent = readsofar * 1e2 / totalsize
            s = f"\rProgress: {percent:5.1f}% [{readsofar / (1024*1024):.1f} MB / {totalsize / (1024*1024):.1f} MB]"
            sys.stdout.write(s)
            sys.stdout.flush()
    urllib.request.urlretrieve(url, str(dest), reporthook)
    print("\nDownload complete.")

def extract_archive(zip_path: Path, target_dir: Path):
    bin_dir = target_dir / "pgsql" / "bin"
    if (bin_dir / "postgres.exe").exists():
        print(f"PostgreSQL already extracted at {target_dir}.")
        return
    print(f"Extracting {zip_path} to {target_dir}...")
    target_dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as zf:
        zf.extractall(target_dir)
    print("Extraction complete.")

def init_and_start_postgres(pg_root: Path, data_dir: Path, log_file: Path):
    bin_dir = pg_root / "pgsql" / "bin"
    initdb = str(bin_dir / "initdb.exe")
    pg_ctl = str(bin_dir / "pg_ctl.exe")
    psql = str(bin_dir / "psql.exe")

    # 1. Initialize data cluster if not present
    if not (data_dir / "PG_VERSION").exists():
        print(f"Initializing PostgreSQL cluster in {data_dir}...")
        data_dir.mkdir(parents=True, exist_ok=True)
        # Using trust auth for initial bootstrap
        cmd_init = [
            initdb,
            "-D", str(data_dir),
            "-U", "postgres",
            "-E", "UTF8",
            "--locale=C",
            "-A", "trust"
        ]
        res = subprocess.run(cmd_init, capture_output=True, text=True)
        if res.returncode != 0:
            print(f"initdb failed: {res.stderr}")
            sys.exit(1)
        print("Database cluster initialized.")

    # 2. Check if postgres is already running
    status_cmd = [pg_ctl, "-D", str(data_dir), "status"]
    status_res = subprocess.run(status_cmd, capture_output=True, text=True)
    if "is running" not in status_res.stdout:
        print(f"Starting PostgreSQL on 127.0.0.1:5432...")
        start_cmd = [
            pg_ctl,
            "-D", str(data_dir),
            "-l", str(log_file),
            "-o", "-h 127.0.0.1 -p 5432",
            "start"
        ]
        subprocess.run(start_cmd, check=True)
        time.sleep(3)
        print("PostgreSQL server started.")
    else:
        print("PostgreSQL server is already running.")

    # 3. Create sentinel_user and sentinel_db if not exist
    print("Configuring user sentinel_user and database sentinel_db...")
    sql_script = """
    DO $$
    BEGIN
        IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'sentinel_user') THEN
            CREATE ROLE sentinel_user WITH LOGIN PASSWORD 'sentinel_secure_pass';
        ELSE
            ALTER ROLE sentinel_user WITH PASSWORD 'sentinel_secure_pass';
        END IF;
    END
    $$;

    SELECT 'CREATE DATABASE sentinel_db OWNER sentinel_user'
    WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = 'sentinel_db')\\gexec

    GRANT ALL PRIVILEGES ON DATABASE sentinel_db TO sentinel_user;
    """
    create_res = subprocess.run(
        [psql, "-h", "127.0.0.1", "-p", "5432", "-U", "postgres", "-c", sql_script],
        capture_output=True, text=True
    )
    print("Postgres config output:", create_res.stdout, create_res.stderr)
    print("\n[SUCCESS] PostgreSQL is up and running on 127.0.0.1:5432")
    print("Connection URL: postgresql+psycopg://sentinel_user:sentinel_secure_pass@127.0.0.1:5432/sentinel_db")

if __name__ == "__main__":
    download_file(DOWNLOAD_URL, ZIP_PATH)
    extract_archive(ZIP_PATH, PG_ROOT)
    init_and_start_postgres(PG_ROOT, DATA_DIR, LOG_FILE)
