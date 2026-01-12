import sys
import os
from sqlalchemy import text

# Add root to sys.path
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), 'api')))
sys.path.append(os.path.abspath(os.path.dirname(__file__)))

from api.index import app, db_session, engine

def migrate():
    print("Migrating database...")
    try:
        with engine.connect() as conn:
            # Check if using Postgres or SQLite
            if 'postgres' in str(engine.url):
                print("Detected PostgreSQL")
                conn.execute(text("ALTER TABLE automezzi ALTER COLUMN targa TYPE VARCHAR(50);"))
            else:
                print("Detected SQLite - Manual handling might be needed if simple alter doesn't work")
                # SQLite doesn't strictly enforce varchar length, so this error implies Postgres.
                # But for completeness:
                # conn.execute(text("ALTER TABLE automezzi ADD COLUMN targa_new VARCHAR(50);")) ...
                pass
                
            conn.commit()
            print("Migration successful: automezzi.targa size increased to 50.")
    except Exception as e:
        print(f"Migration failed: {e}")

if __name__ == "__main__":
    migrate()
