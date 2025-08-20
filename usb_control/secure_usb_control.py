import os
import secrets
import smtplib
import sqlite3
import subprocess
import hashlib
import time
from datetime import datetime, timedelta
from email.message import EmailMessage
import tkinter as tk
from tkinter import messagebox
import cv2  # for webcam capture
from email.mime.image import MIMEImage
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import smtplib
# CONFIG - Use environment variables for sensitive info
SMTP_HOST = os.getenv("SMTP_HOST")    # e.g. "smtp.gmail.com"
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")    # App password or SMTP password
FROM_ADDR = SMTP_USER
OTP_TTL_SECONDS = 300   # 5 minutes
MAX_ATTEMPTS = 3
DB_PATH = "usb_control.db"

# === Database helpers ===
def init_db():
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = conn.cursor()
    cur.execute("""CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY,
                    email TEXT UNIQUE,
                    name TEXT
                  )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS otps (
                    id INTEGER PRIMARY KEY,
                    user_email TEXT,
                    otp_hash TEXT,
                    expires_at TIMESTAMP,
                    attempts INTEGER DEFAULT 0
                  )""")
    cur.execute("""CREATE TABLE IF NOT EXISTS logs (
                    id INTEGER PRIMARY KEY,
                    user_email TEXT,
                    action TEXT,
                    status TEXT,
                    details TEXT,
                    ts TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                  )""")
    conn.commit()
    conn.close()

def log_event(user_email, action, status, details=""):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("INSERT INTO logs (user_email, action, status, details) VALUES (?, ?, ?, ?)",
                (user_email, action, status, details))
    conn.commit()
    conn.close()

# === OTP generation and storage ===
def generate_otp():
    return f"{secrets.randbelow(10**6):06d}"

def hash_otp(otp):
    salt = secrets.token_hex(8)
    h = hashlib.sha256((salt + otp).encode('utf-8')).hexdigest()
    return f"{salt}${h}"

def verify_otp_hash(stored_hash, entered_otp):
    salt, h = stored_hash.split("$")
    return hashlib.sha256((salt + entered_otp).encode('utf-8')).hexdigest() == h

def store_otp_for_user(email, otp_plain):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    expires_at = datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)
    cur.execute("DELETE FROM otps WHERE user_email = ?", (email,))
    cur.execute("INSERT INTO otps (user_email, otp_hash, expires_at, attempts) VALUES (?, ?, ?, 0)",
                (email, hash_otp(otp_plain), expires_at))
    conn.commit()
    conn.close()

def get_otp_record(email):
    conn = sqlite3.connect(DB_PATH, detect_types=sqlite3.PARSE_DECLTYPES)
    cur = conn.cursor()
    cur.execute("SELECT id, otp_hash, expires_at, attempts FROM otps WHERE user_email = ?", (email,))
    row = cur.fetchone()
    conn.close()
    return row

def increment_attempts(otp_id):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE otps SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
    conn.commit()
    cur.execute("SELECT attempts FROM otps WHERE id = ?", (otp_id,))
    a = cur.fetchone()[0]
    conn.close()
    return a

def remove_otp(email):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM otps WHERE user_email = ?", (email,))
    conn.commit()
    conn.close()

# === Email sending ===
def send_email(to_addr, subject, body):
    if not all([SMTP_HOST, SMTP_PORT, SMTP_USER, SMTP_PASS]):
        raise RuntimeError("SMTP config missing. Set SMTP_HOST, SMTP_USER, SMTP_PASS env vars.")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = FROM_ADDR
    msg["To"] = to_addr
    msg.set_content(body)
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as s:
        s.ehlo()
        s.starttls()
        s.ehlo()
        s.login(SMTP_USER, SMTP_PASS)
        s.send_message(msg)

# === Webcam capture (optional) ===
def capture_webcam_image(save_path="intruder.jpg"):
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if ret:
            cv2.imwrite(save_path, frame)
        cap.release()
        return ret
    except Exception as e:
        print("webcam capture failed:", e)
        return False

# === Registry change scripts ===
def run_block_script():
    import sys
    if sys.platform.startswith("win"):
        subprocess.run(["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                        "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"], check=True)
    else:
        raise RuntimeError("Only supported on Windows")

def run_unblock_script():
    import sys
    if sys.platform.startswith("win"):
        subprocess.run(["reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
                        "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"], check=True)
    else:
        raise RuntimeError("Only supported on Windows")

# === High-level flow ===
def initiate_action(email, action):
    otp = generate_otp()
    store_otp_for_user(email, otp)
    subject = f"Your OTP for USB {action.capitalize()}"
    body = f"Your one-time code to {action} USB ports is: {otp}\nThis code expires in {OTP_TTL_SECONDS//60} minutes."
    send_email(email, subject, body)
    log_event(email, action, "OTP_SENT", f"otp_ttl={OTP_TTL_SECONDS}s")
    return True

def validate_and_execute(email, entered_otp, action):
    rec = get_otp_record(email)
    if not rec:
        log_event(email, action, "NO_OTP")
        return False, "No OTP found or it expired. Request a new one."

    otp_id, otp_hash, expires_at, attempts = rec

    # Handle datetime or string from DB
    if isinstance(expires_at, str):
        expires_dt = datetime.fromisoformat(expires_at)
    else:
        expires_dt = expires_at

    # OTP expired
    if datetime.utcnow() > expires_dt:
        remove_otp(email)
        log_event(email, action, "OTP_EXPIRED")
        return False, "OTP expired. Request a new one."

    # OTP incorrect
    if not verify_otp_hash(otp_hash, entered_otp):
        attempts_after = increment_attempts(otp_id)
        log_event(email, action, "OTP_FAIL", f"attempts={attempts_after}")

        if attempts_after >= MAX_ATTEMPTS:
            fname = f"intruder_{int(time.time())}.jpg"
            captured = capture_webcam_image(fname)
            log_event(email, action, "INTRUDER_CAPTURE",
                      f"captured={captured}, file={fname}")
            remove_otp(email)

            # Try to email intruder photo
            try:
                msg = MIMEMultipart()
                msg['Subject'] = 'INTRUDER ALERT: USB Security'
                msg['From'] = FROM_ADDR
                msg['To'] = email  # Or replace with admin email

                body_text = f"""
                Intruder detected on the system.
                Action attempted: {action}
                OTP Attempts: {attempts_after}
                Photo captured: {fname}
                """
                msg.attach(MIMEText(body_text, 'plain'))

                with open(fname, 'rb') as f:
                    img_data = f.read()
                msg.attach(MIMEImage(img_data, name=fname))

                with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
                    server.starttls()
                    server.login(SMTP_USER, SMTP_PASS)
                    server.sendmail(FROM_ADDR, [email], msg.as_string())

                print(f"[INFO] Intruder photo emailed to {email}")

            except Exception as e:
                print(f"[ERROR] Failed to send intruder email: {e}")

            return False, f"Maximum attempts exceeded. Intruder capture saved and sent to admin: {fname}"

        # OTP wrong but attempts still left
        return False, f"Invalid OTP. Attempts left: {MAX_ATTEMPTS - attempts_after}"

    # OTP correct — run the action
    try:
        if action == "disable":
            run_block_script()
        else:
            run_unblock_script()

        remove_otp(email)
        log_event(email, action, "SUCCESS")
        return True, f"USB {action}d successfully."

    except Exception as e:
        log_event(email, action, "ERROR", str(e))
        return False, f"Failed to {action} USB: {e}"

# === Tkinter UI helper ===
def prompt_and_send(root, user_email, action):
    try:
        initiate_action(user_email, action)
    except Exception as e:
        messagebox.showerror("Email error", f"Could not send OTP: {e}")
        return

    w = tk.Toplevel(root)
    w.title("Enter OTP")
    tk.Label(w, text=f"An OTP was sent to {user_email}. Enter it below:").pack(padx=8, pady=6)
    ent = tk.Entry(w)
    ent.pack(padx=8, pady=6)
    status = tk.Label(w, text="")
    status.pack()

    def on_ok():
        ok = ent.get().strip()
        ok_status, msg = validate_and_execute(user_email, ok, action)
        if ok_status:
            messagebox.showinfo("Success", msg)
            w.destroy()
        else:
            status.config(text=msg)
    tk.Button(w, text="OK", command=on_ok).pack(pady=6)

# Init DB
init_db()
