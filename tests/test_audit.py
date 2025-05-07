from audit import AuditLogger
import sqlite3

def test_audit_logging():
    # Setup
    conn = sqlite3.connect('encrypted_data.db')
    conn.execute("CREATE TABLE IF NOT EXISTS audit_logs (id INTEGER PRIMARY KEY, action TEXT, user TEXT, timestamp DATETIME DEFAULT CURRENT_TIMESTAMP)")
    conn.close()
    
    # Test
    test_action = "access_data"
    AuditLogger.log_action(test_action, "tester")
    
    logs = AuditLogger.get_logs()
    assert len(logs) > 0
    assert logs[0][1] == test_action
    assert logs[0][2] == "tester"