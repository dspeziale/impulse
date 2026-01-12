import sqlite3
import os

db_path = os.path.join('instance', 'impulse.db')

if not os.path.exists(db_path):
    # Try alternate path if not found in instance
    db_path = 'impulse.db'

if not os.path.exists(db_path):
    print(f"Database not found at {db_path}")
    exit(1)

print(f"Migrating database at {db_path}...")

conn = sqlite3.connect(db_path)
cursor = conn.cursor()

try:
    cursor.execute("ALTER TABLE timbrature ADD COLUMN note TEXT")
    conn.commit()
    print("Column 'note' added successfully.")
except sqlite3.OperationalError as e:
    if "duplicate column name" in str(e):
        print("Column 'note' already exists.")
    else:
        print(f"Error: {e}")
finally:
    conn.close()
