import sqlite3
import os

DB_PATH = "internship.db"

def migrate():
    if not os.path.exists(DB_PATH):
        print("No database found to migrate.")
        return

    print(f"Connecting to {DB_PATH}...")
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row

    try:
        # 1. Backfill user_sessions
        print("Backfilling user_sessions...")
        # Since SQLite ALTER TABLE is limited, we might not need to alter if the app.py change creates it on fresh installs.
        # But for existing DBs, we must add the columns.
        try:
            conn.execute("ALTER TABLE user_sessions ADD COLUMN user_id INTEGER")
        except sqlite3.OperationalError:
            pass # Column exists
            
        conn.execute("""
            UPDATE user_sessions 
            SET user_id = (SELECT id FROM intern_accounts WHERE intern_accounts.email = user_sessions.email) 
            WHERE role = 'intern' AND user_id IS NULL
        """)

        # 2. Backfill enrollments
        print("Backfilling enrollments...")
        try:
            conn.execute("ALTER TABLE enrollments ADD COLUMN intern_id INTEGER")
        except sqlite3.OperationalError:
            pass
            
        conn.execute("""
            UPDATE enrollments 
            SET intern_id = (SELECT id FROM intern_accounts WHERE intern_accounts.email = enrollments.email)
            WHERE intern_id IS NULL
        """)

        # 3. Backfill interviews
        print("Backfilling interviews...")
        try:
            conn.execute("ALTER TABLE interviews ADD COLUMN intern_id INTEGER")
        except sqlite3.OperationalError:
            pass
            
        conn.execute("""
            UPDATE interviews 
            SET intern_id = (SELECT id FROM intern_accounts WHERE intern_accounts.email = interviews.email)
            WHERE intern_id IS NULL
        """)

        # 4. Backfill device_profiles
        print("Backfilling device_profiles...")
        try:
            conn.execute("ALTER TABLE device_profiles ADD COLUMN intern_id INTEGER")
        except sqlite3.OperationalError:
            pass
            
        conn.execute("""
            UPDATE device_profiles 
            SET intern_id = (SELECT id FROM intern_accounts WHERE intern_accounts.email = device_profiles.email)
            WHERE intern_id IS NULL AND email IS NOT NULL
        """)

        conn.commit()
        print("Migration successful! Immutable ID columns have been populated.")
        
    except Exception as e:
        print(f"Migration failed: {e}")
        conn.rollback()
    finally:
        conn.close()

if __name__ == "__main__":
    migrate()
