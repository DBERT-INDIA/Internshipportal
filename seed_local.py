import os
from app import app, init_db, get_db, set_password_hash

def seed():
    with app.app_context():
        # init db just in case
        init_db()
        with get_db() as conn:
            # Intern
            conn.execute("INSERT OR IGNORE INTO intern_accounts (name, email, password_hash, password_set, is_active) VALUES (?,?,?,1,1)",
                         ("Test Intern", "intern@example.com", set_password_hash("Password123")))
            # Company
            conn.execute("INSERT OR IGNORE INTO companies (name, email, password_hash, is_active, is_approved) VALUES (?,?,?,1,1)",
                         ("Test Corp", "company@example.com", set_password_hash("Password123")))
            # Staff
            conn.execute("INSERT OR IGNORE INTO staff_accounts (name, email, password_hash, is_active) VALUES (?, ?, ?, 1)",
                         ("Test Staff", "staff@example.com", set_password_hash("Password123")))
            # Admin (Admin role might just be checking if email == ADMIN_USERNAME, wait, let me check admin login)
            conn.execute("INSERT OR IGNORE INTO staff_accounts (name, email, password_hash, is_active) VALUES (?, ?, ?, 1)",
                         ("Test Admin", "admin@example.com", set_password_hash("Password123")))
            # Mentor
            conn.execute("INSERT OR IGNORE INTO mentors (name, email, password_hash) VALUES (?, ?, ?)",
                         ("Test Mentor", "mentor@example.com", set_password_hash("Password123")))
            conn.commit()
            print("Seeded successfully.")

if __name__ == "__main__":
    seed()

