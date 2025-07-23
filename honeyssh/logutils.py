from __future__ import annotations
import os
import json
import csv
import sqlite3
import logging
from datetime import datetime, timedelta
from logging.handlers import RotatingFileHandler
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.mime.application import MIMEApplication
import smtplib
from fpdf import FPDF
from . import config
from .constants import (
    ALERT_FROM,
    ALERT_TO,
    SMTP_HOST,
    SMTP_PORT,
    SMTP_USER,
    SMTP_PASS,
)


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_record = {
            "timestamp": datetime.utcfromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "message": record.getMessage(),
        }
        return json.dumps(log_record)


def setup_logging() -> logging.Logger:
    os.makedirs(config.LOG_DIR, exist_ok=True)
    handler = RotatingFileHandler(config.LOG_FILE, maxBytes=10240, backupCount=5)
    handler.setFormatter(JsonFormatter())
    logger = logging.getLogger("honey")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)
    return logger


LOGGER = setup_logging()


def log_human_readable(timestamp: str, client_ip: str, username: str, event_type: str, details: str) -> None:
    os.makedirs(config.LOG_DIR, exist_ok=True)
    with open(config.ALERT_LOG_FILE, "a", newline="") as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([timestamp, client_ip, username, event_type, details])


def trigger_alert(session_id: int, event_type: str, details: str, client_ip: str, username: str) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    print(f"\033[91m[ALERT]\033[0m {timestamp} {client_ip} {username}: {event_type} - {details}")
    log_event = not (session_id < 0 or username == "system" or client_ip == "system")
    if log_event:
        log_human_readable(timestamp, client_ip, username, event_type, details)
    try:
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
            smtp.starttls()
            smtp.login(SMTP_USER, SMTP_PASS)
            subject = f"ALERTE SÉCURITÉ - {event_type}"
            body = (
                f"🚨 [ALERTE SÉCURITÉ - {event_type}]\n\n"
                f"- Utilisateur      : {username}\n"
                f"- Adresse IP       : {client_ip}\n"
                f"- Heure exacte     : {timestamp}\n"
                f"- Session ID       : {session_id}\n\n"
                f"Détails : {details}"
            )
            msg = MIMEText(body)
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            smtp.send_message(msg)
    except smtplib.SMTPException as e:
        print(f"[!] SMTP error: {str(e)}")
    if log_event:
        try:
            with sqlite3.connect(config.DB_NAME, uri=True) as conn:
                conn.execute(
                    "INSERT INTO events (timestamp, ip, username, event_type, details) VALUES (?, ?, ?, ?, ?)",
                    (timestamp, client_ip, username, event_type, details),
                )
        except sqlite3.Error as e:
            print(f"[!] DB error: {e}")


def log_activity(session_id: int, client_ip: str, username: str, key: str) -> None:
    from .constants import ANSI_KEY_LABELS, KEY_DISPLAY_MODE
    key = ANSI_KEY_LABELS.get(key, key)
    if KEY_DISPLAY_MODE != "full":
        if (len(key) == 1 and key.isprintable()) or key in ["\n", "\r", "\t", "\x7f", "\x08"]:
            return
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")
    log_entry = {
        "event": "keypress",
        "time": timestamp,
        "session": session_id,
        "ip": client_ip,
        "user": username,
        "key": key,
    }
    LOGGER.info(json.dumps(log_entry))
    if KEY_DISPLAY_MODE == "full":
        print(f"\033[95m[KEY]\033[0m {timestamp} {username}@{client_ip}: {repr(key)}")
    elif KEY_DISPLAY_MODE == "filtered":
        print(f"\033[95m[KEY]\033[0m {username}@{client_ip}: {repr(key)}")


def log_session_activity(
    session_id: int,
    client_ip: str,
    username: str,
    command_line: str,
    output: str,
    success: bool | None = None,
    cwd: str | None = None,
    cmd_index: int | None = None,
    start_time: str | None = None,
    end_time: str | None = None,
) -> None:
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = {
        "event": "command",
        "time": timestamp,
        "session": session_id,
        "ip": client_ip,
        "user": username,
        "command": command_line,
        "output": output,
    }
    if cwd is not None:
        log_entry["cwd"] = cwd
    if cmd_index is not None:
        log_entry["index"] = cmd_index
    if start_time is not None:
        log_entry["start_time"] = start_time
    if end_time is not None:
        log_entry["end_time"] = end_time
        if start_time is not None:
            duration_ms = (datetime.fromisoformat(end_time) - datetime.fromisoformat(start_time)).total_seconds() * 1000
            log_entry["duration_ms"] = int(duration_ms)
    if success is not None:
        log_entry["success"] = success
    LOGGER.info(json.dumps(log_entry))
    if success is None:
        status_text = "in-progress"
    else:
        status_text = "success" if success else "failure"
    duration_msg = f", {log_entry['duration_ms']}ms" if "duration_ms" in log_entry else ""
    index_msg = f"#{cmd_index} " if cmd_index is not None else ""
    cwd_msg = f"[{cwd}] " if cwd is not None else ""
    print(
        f"\033[96m[SESSION]\033[0m {timestamp} {username}@{client_ip} {cwd_msg}{index_msg}{command_line} -> {output} ({status_text}{duration_msg})"
    )


def generate_report(period: str) -> str:
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("Arial", "B", 16)
    pdf.cell(0, 10, f"System Activity Report - {period}", 0, 1, "C")
    pdf.set_font("Arial", size=12)
    start_time = (datetime.now() - timedelta(minutes=15 if period == "15min" else 60 if period == "hourly" else 10080)).strftime("%Y-%m-%d %H:%M:%S")
    pdf.cell(0, 10, f"Period: {start_time} to {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", 0, 1)
    pdf.ln(5)
    try:
        with sqlite3.connect(config.DB_NAME, uri=True) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,))
            login_count = cur.fetchone()[0]
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Login Attempts", 0, 1)
            pdf.set_font("Arial", size=12)
            pdf.cell(0, 10, f"Total: {login_count}", 0, 1)
            cur.execute(
                "SELECT ip, COUNT(*) as count FROM login_attempts WHERE timestamp > ? GROUP BY ip ORDER BY count DESC LIMIT 5",
                (start_time,),
            )
            for ip, count in cur.fetchall():
                pdf.cell(0, 10, f"{ip} - {count} attempts", 0, 1)
            pdf.ln(2)
            cur.execute(
                "SELECT command, COUNT(*) as count FROM commands WHERE timestamp > ? GROUP BY command ORDER BY count DESC LIMIT 5",
                (start_time,),
            )
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Top Commands", 0, 1)
            pdf.set_font("Arial", size=12)
            for cmd, count in cur.fetchall():
                pdf.cell(0, 10, f"{cmd} - {count} executions", 0, 1)
            pdf.ln(2)
            cur.execute(
                "SELECT event_type, COUNT(*) as count FROM events WHERE timestamp > ? GROUP BY event_type ORDER BY count DESC",
                (start_time,),
            )
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Event Counts", 0, 1)
            pdf.set_font("Arial", size=12)
            for event_type, count in cur.fetchall():
                pdf.cell(0, 10, f"{event_type}: {count}", 0, 1)
            pdf.ln(2)
            cur.execute(
                "SELECT timestamp, ip, username, event_type, details FROM events WHERE timestamp > ? ORDER BY timestamp DESC LIMIT 10",
                (start_time,),
            )
            pdf.set_font("Arial", "B", 12)
            pdf.cell(0, 10, "Recent Events", 0, 1)
            pdf.set_font("Arial", size=12)
            for ts, ip, user, event_type, details in cur.fetchall():
                pdf.cell(0, 10, f"{ts} - {ip} ({user}): {event_type} - {details}", 0, 1)
    except sqlite3.Error as e:
        print(f"[!] Report error: {e}")
    report_filename = f"{period}_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.pdf"
    pdf.output(report_filename)
    return report_filename


def has_recent_activity() -> bool:
    start_time = (datetime.now() - timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
    try:
        with sqlite3.connect(config.DB_NAME, uri=True) as conn:
            cur = conn.cursor()
            cur.execute("SELECT COUNT(*) FROM login_attempts WHERE timestamp > ?", (start_time,))
            if cur.fetchone()[0] > 0:
                return True
            cur.execute("SELECT COUNT(*) FROM commands WHERE timestamp > ?", (start_time,))
            if cur.fetchone()[0] > 0:
                return True
            cur.execute(
                "SELECT COUNT(*) FROM events WHERE timestamp > ? AND username != 'system'",
                (start_time,),
            )
            if cur.fetchone()[0] > 0:
                return True
    except sqlite3.Error as e:
        print(f"[!] Activity check error: {e}")
    return False


def send_weekly_report() -> None:
    while True:
        now = datetime.now()
        if now.weekday() == 0 and now.hour == 8:
            report_filename = generate_report("weekly")
            subject = f"Weekly System Report - {datetime.now().strftime('%Y-%m-%d')}"
            body = "Attached is the weekly system activity report."
            msg = MIMEMultipart()
            msg["From"] = ALERT_FROM
            msg["To"] = ALERT_TO
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))
            with open(report_filename, "rb") as f:
                part = MIMEApplication(f.read(), Name=os.path.basename(report_filename))
                part["Content-Disposition"] = f'attachment; filename="{os.path.basename(report_filename)}"'
                msg.attach(part)
            try:
                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                    smtp.starttls()
                    smtp.login(SMTP_USER, SMTP_PASS)
                    smtp.send_message(msg)
                print(f"Weekly report sent: {report_filename}")
            except Exception as e:
                print(f"Weekly report email error: {e}")
            finally:
                if os.path.exists(report_filename):
                    os.remove(report_filename)
        time.sleep(3600)


def send_periodic_report() -> None:
    while True:
        time.sleep(900)
        if not has_recent_activity():
            continue
        report_filename = generate_report("15min")
        subject = f"15-Minute System Report - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"
        body = "Attached is the latest 15-minute activity report."
        msg = MIMEMultipart()
        msg["From"] = ALERT_FROM
        msg["To"] = ALERT_TO
        msg["Subject"] = subject
        msg.attach(MIMEText(body, "plain"))
        with open(report_filename, "rb") as f:
            part = MIMEApplication(f.read(), Name=os.path.basename(report_filename))
            part["Content-Disposition"] = f'attachment; filename="{os.path.basename(report_filename)}"'
            msg.attach(part)
        try:
            with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as smtp:
                smtp.starttls()
                smtp.login(SMTP_USER, SMTP_PASS)
                smtp.send_message(msg)
            print(f"Periodic report sent: {report_filename}")
        except Exception as e:
            print(f"Periodic report email error: {e}")
        finally:
            if os.path.exists(report_filename):
                os.remove(report_filename)


__all__ = [
    "LOGGER",
    "log_activity",
    "log_session_activity",
    "trigger_alert",
    "generate_report",
    "send_weekly_report",
    "send_periodic_report",
]
