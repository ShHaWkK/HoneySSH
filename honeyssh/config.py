HOST = ""  # Listen on all interfaces
PORT = 2224  # Custom port
SSH_BANNER = "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1"
ENABLE_REDIRECTION = False
REAL_SSH_HOST = "192.168.1.100"
REAL_SSH_PORT = 22

DB_NAME = "file:honey?mode=memory&cache=shared"
FS_DB = "file:filesystem?mode=memory&cache=shared"

SESSION_LOG_DIR = "session_logs"
LOG_DIR = "logs"
LOG_FILE = LOG_DIR + "/honey.log"
ALERT_LOG_FILE = LOG_DIR + "/alerts.log"
