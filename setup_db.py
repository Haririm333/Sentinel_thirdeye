import psycopg

def setup():
    conn = psycopg.connect("host=127.0.0.1 port=5432 user=postgres dbname=postgres", autocommit=True)
    cur = conn.cursor()
    cur.execute("SELECT 1 FROM pg_roles WHERE rolname='sentinel_user'")
    if not cur.fetchone():
        cur.execute("CREATE ROLE sentinel_user WITH LOGIN PASSWORD 'sentinel_secure_pass'")
        print("Created role sentinel_user")
    else:
        cur.execute("ALTER ROLE sentinel_user WITH PASSWORD 'sentinel_secure_pass'")
        print("Updated role sentinel_user")

    cur.execute("SELECT 1 FROM pg_database WHERE datname='sentinel_db'")
    if not cur.fetchone():
        cur.execute("CREATE DATABASE sentinel_db OWNER sentinel_user")
        print("Created database sentinel_db")
    else:
        print("Database sentinel_db already exists")

    conn.close()

    # Test connecting as sentinel_user to sentinel_db
    conn2 = psycopg.connect("host=127.0.0.1 port=5432 user=sentinel_user password=sentinel_secure_pass dbname=sentinel_db")
    print("SUCCESS: Connected as sentinel_user to sentinel_db! Server version:", conn2.info.server_version)
    conn2.close()

if __name__ == "__main__":
    setup()
