import sqlite3
from datetime import datetime

class AuditLogger:
    @staticmethod
    def log_action(action: str, user: str = "system"):
        conn = sqlite3.connect('encrypted_data.db')
        try:
            conn.execute(
                "INSERT INTO audit_logs (action, user) VALUES (?, ?)",
                (action, user)
            )
            conn.commit()
        except sqlite3.Error as e:
            print("Audit log error:", str(e))
        finally:
            conn.close()

    @staticmethod
    def get_logs():
        conn = sqlite3.connect('encrypted_data.db')
        logs = conn.execute(
            "SELECT id, action, user, timestamp FROM audit_logs ORDER BY timestamp DESC"
        ).fetchall()
        conn.close()
        return logs