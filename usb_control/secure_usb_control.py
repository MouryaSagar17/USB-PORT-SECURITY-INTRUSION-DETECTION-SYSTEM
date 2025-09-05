"""
USB Physical Security - Single-file Reference Implementation with Modern UI
- SQLite DB for users, otps, logs
- SMTP email for OTPs and notifications (config via env)
- OTP lifecycle with rate-limiting and attempt limits
- Intruder capture via OpenCV and send via email to admin
- Registry-based USB enable/disable (Windows only) with admin-checks
- Modern Tkinter GUI with red/black professional theme
"""
import os
import secrets
import sqlite3
import hashlib
from datetime import datetime, timedelta
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.image import MIMEImage
import sys
import subprocess
import threading
import logging
import ctypes
import webbrowser
# Optional imports (handle gracefully if missing)
try:
    import cv2
except Exception:
    cv2 = None
try:
    import bcrypt
except Exception:
    bcrypt = None
try:
    import tkinter as tk
    from tkinter import ttk, messagebox, simpledialog, font
    from tkinter.scrolledtext import ScrolledText
except Exception:
    tk = None

# Try to import PIL for images
try:
    from PIL import Image, ImageTk
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ---------------- Configuration ----------------
DB_PATH = os.getenv("DB_PATH", "usb_control.db")
SMTP_HOST = os.getenv("SMTP_HOST")
SMTP_PORT = int(os.getenv("SMTP_PORT", "587"))
SMTP_USER = os.getenv("SMTP_USER")
SMTP_PASS = os.getenv("SMTP_PASS")
FROM_ADDR = SMTP_USER or "no-reply@example.com"
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL")
OTP_TTL_SECONDS = int(os.getenv("OTP_TTL_SECONDS", "300"))
MAX_ATTEMPTS = int(os.getenv("MAX_ATTEMPTS", "3"))
RATE_LIMIT_MAX = int(os.getenv("RATE_LIMIT_MAX", "150"))
RATE_LIMIT_WINDOW_MIN = int(os.getenv("RATE_LIMIT_WINDOW_MIN", "10"))
INTRUDER_IMAGE_PREFIX = os.getenv("INTRUDER_IMAGE_PREFIX", "intruder")
BOOTSTRAP_ADMIN_EMAIL = os.getenv("BOOTSTRAP_ADMIN_EMAIL", "admin@localhost")
LOG_LEVEL = os.getenv("LOG_LEVEL", "INFO")

# UI Colors
DARK_BG = "#1a1a1a"
LIGHT_BG = "#2d2d2d"
RED_ACCENT = "#dc2626"
WHITE_TEXT = "#ffffff"
GRAY_TEXT = "#a0a0a0"
SUCCESS_GREEN = "#16a34a"
ERROR_RED = "#dc2626"

# ---------------- Logging ----------------
logging.basicConfig(level=getattr(logging, LOG_LEVEL.upper(), logging.INFO),
                    format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("usb_security")

# ---------------- Database Service ----------------
class DBService:
    def __init__(self, path=DB_PATH):
        self.path = path
        self._init_db()
    
    def _conn(self):
        return sqlite3.connect(self.path)
    
    def _init_db(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("""CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY,
                        email TEXT UNIQUE,
                        name TEXT,
                        pwd_hash TEXT,
                        is_admin INTEGER DEFAULT 0,
                        is_enabled INTEGER DEFAULT 1,
                        created_at TEXT
                        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS otps (
                        id INTEGER PRIMARY KEY,
                        user_email TEXT,
                        otp_hash TEXT,
                        salt TEXT,
                        expires_at TEXT,
                        attempts INTEGER DEFAULT 0,
                        created_at TEXT
                        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS otp_requests (
                        id INTEGER PRIMARY KEY,
                        user_email TEXT,
                        ts TEXT
                        )""")
        cur.execute("""CREATE TABLE IF NOT EXISTS logs (
                        id INTEGER PRIMARY KEY,
                        user_email TEXT,
                        action TEXT,
                        status TEXT,
                        details TEXT,
                        ts TEXT DEFAULT (datetime('now'))
                        )""")
        conn.commit()
        conn.close()
    
    # Users
    def create_user(self, email, name, pwd_hash, is_admin=False, is_enabled=True):
        conn = self._conn()
        cur = conn.cursor()
        try:
            cur.execute("INSERT INTO users (email, name, pwd_hash, is_admin, is_enabled, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                        (email.lower(), name, pwd_hash, 1 if is_admin else 0, 1 if is_enabled else 0, datetime.utcnow().isoformat()))
            conn.commit()
            return True, None
        except sqlite3.IntegrityError:
            return False, "User already exists"
        except Exception as e:
            return False, str(e)
        finally:
            conn.close()
    
    def get_user(self, email):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id, email, name, pwd_hash, is_admin, is_enabled, created_at FROM users WHERE email = ?", (email.lower(),))
        row = cur.fetchone()
        conn.close()
        return row
    
    def list_users(self):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT email, name, is_admin, is_enabled, created_at FROM users ORDER BY email ASC")
        rows = cur.fetchall()
        conn.close()
        return rows
    
    def set_user_enabled(self, email, enabled: bool):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_enabled = ? WHERE email = ?", (1 if enabled else 0, email.lower()))
        conn.commit()
        conn.close()
    
    def update_user_password(self, email, pwd_hash):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET pwd_hash = ? WHERE email = ?", (pwd_hash, email.lower()))
        conn.commit()
        conn.close()
    def set_user_admin(self, email, is_admin: bool):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("UPDATE users SET is_admin = ? WHERE email = ?", (1 if is_admin else 0, email.lower()))
        conn.commit()
        conn.close()

    def delete_user(self, email):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM users WHERE email = ?", (email.lower(),))
        conn.commit()
        conn.close()

    # OTPs
    def store_otp(self, email, otp_hash, salt, expires_at_iso):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM otps WHERE user_email = ?", (email.lower(),))
        cur.execute("INSERT INTO otps (user_email, otp_hash, salt, expires_at, attempts, created_at) VALUES (?, ?, ?, ?, 0, ?)",
                    (email.lower(), otp_hash, salt, expires_at_iso, datetime.utcnow().isoformat()))
        cur.execute("INSERT INTO otp_requests (user_email, ts) VALUES (?, ?)", (email.lower(), datetime.utcnow().isoformat()))
        conn.commit()
        conn.close()
    
    def get_otp(self, email):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT id, otp_hash, salt, expires_at, attempts FROM otps WHERE user_email = ?", (email.lower(),))
        row = cur.fetchone()
        conn.close()
        return row
    
    def increment_otp_attempts(self, otp_id):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("UPDATE otps SET attempts = attempts + 1 WHERE id = ?", (otp_id,))
        conn.commit()
        cur.execute("SELECT attempts FROM otps WHERE id = ?", (otp_id,))
        a = cur.fetchone()[0]
        conn.close()
        return a
    
    def remove_otp(self, email):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("DELETE FROM otps WHERE user_email = ?", (email.lower(),))
        conn.commit()
        conn.close()
    
    def requests_in_window(self, email, minutes):
        window_start = datetime.utcnow() - timedelta(minutes=minutes)
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM otp_requests WHERE user_email = ? AND ts >= ?", (email.lower(), window_start.isoformat()))
        c = cur.fetchone()[0]
        conn.close()
        return c
    
    # Logs
    def log_event(self, user_email, action, status, details=""):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("INSERT INTO logs (user_email, action, status, details) VALUES (?, ?, ?, ?)",
                    (user_email, action, status, details))
        conn.commit()
        conn.close()
    
    def get_logs(self, limit=200):
        conn = self._conn()
        cur = conn.cursor()
        cur.execute("SELECT ts, user_email, action, status, details FROM logs ORDER BY ts DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

# ---------------- Utilities ----------------
class CryptoUtils:
    @staticmethod
    def hash_password(password: str) -> str:
        if bcrypt:
            return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode()
        return hashlib.sha256(password.encode("utf-8")).hexdigest()
    
    @staticmethod
    def verify_password(stored_hash: str, password: str) -> bool:
        if bcrypt:
            try:
                return bcrypt.checkpw(password.encode("utf-8"), stored_hash.encode("utf-8"))
            except Exception:
                return False
        return hashlib.sha256(password.encode("utf-8")).hexdigest() == stored_hash
    
    @staticmethod
    def gen_otp():
        return f"{secrets.randbelow(10**6):06d}"
    
    @staticmethod
    def hash_otp_with_salt(otp: str):
        salt = secrets.token_hex(8)
        h = hashlib.sha256((salt + otp).encode("utf-8")).hexdigest()
        return salt, h

# ---------------- Email Service ----------------
class EmailService:
    def __init__(self, host=SMTP_HOST, port=SMTP_PORT, user=SMTP_USER, passwd=SMTP_PASS, from_addr=FROM_ADDR):
        self.host = host
        self.port = port
        self.user = user
        self.passwd = passwd
        self.from_addr = from_addr
    
    def send(self, to_addr, subject, body, attachments=None):
        if not all([self.host, self.port, self.user, self.passwd]):
            raise RuntimeError("SMTP not configured. Set SMTP_HOST, SMTP_USER and SMTP_PASS environment vars.")
        msg = MIMEMultipart()
        msg['Subject'] = subject
        msg['From'] = self.from_addr
        msg['To'] = to_addr
        msg.attach(MIMEText(body, 'plain'))
        if attachments:
            for a in attachments:
                try:
                    with open(a, 'rb') as f:
                        data = f.read()
                    if a.lower().endswith(('.png', '.jpg', '.jpeg')):
                        img = MIMEImage(data, name=os.path.basename(a))
                        msg.attach(img)
                    else:
                        part = MIMEText(data, 'base64')
                        part.add_header('Content-Disposition', 'attachment', filename=os.path.basename(a))
                        msg.attach(part)
                except Exception as e:
                    logger.warning('Attachment %s failed: %s', a, e)
        s = smtplib.SMTP(self.host, self.port)
        try:
            s.ehlo()
            s.starttls()
            s.login(self.user, self.passwd)
            s.send_message(msg)
        finally:
            s.quit()

# ---------------- Intruder Detector ----------------
class IntruderDetector:
    def __init__(self, image_prefix=INTRUDER_IMAGE_PREFIX):
        self.image_prefix = image_prefix
    
    def capture(self):
        if not cv2:
            logger.error('OpenCV not available; cannot capture intruder image')
            return False, None
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            logger.error('Webcam not available')
            return False, None
        ret, frame = cap.read()
        cap.release()
        if not ret:
            return False, None
        fname = f"{self.image_prefix}_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.jpg"
        cv2.imwrite(fname, frame)
        return True, fname

# ---------------- USB Controller (Windows registry) ----------------
class USBController:
    @staticmethod
    def is_windows():
        """Check if the OS is Windows"""
        return sys.platform.startswith("win")

    @staticmethod
    def is_admin_windows():
        """Check if script has admin privileges"""
        if not USBController.is_windows():
            return False
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    @staticmethod
    def run_block_script():
        """Disable USB ports via registry"""
        if not USBController.is_windows():
            raise RuntimeError("Registry USB control is only supported on Windows")
        if not USBController.is_admin_windows():
            raise PermissionError("Admin privileges required to modify registry")
        subprocess.run([
            "reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
            "/v", "Start", "/t", "REG_DWORD", "/d", "4", "/f"
        ], check=True)

    @staticmethod
    def run_unblock_script():
        """Enable USB ports via registry"""
        if not USBController.is_windows():
            raise RuntimeError("Registry USB control is only supported on Windows")
        if not USBController.is_admin_windows():
            raise PermissionError("Admin privileges required to modify registry")
        subprocess.run([
            "reg", "add", r"HKLM\SYSTEM\CurrentControlSet\Services\USBSTOR",
            "/v", "Start", "/t", "REG_DWORD", "/d", "3", "/f"
        ], check=True)
# ---------------- Application Logic (OTP + flows) ----------------
class AppCore:
    def __init__(self, db: DBService, email_svc: EmailService, intruder: IntruderDetector=None):
        self.db = db
        self.email = email_svc
        self.intruder = intruder
    
    def bootstrap_admin_if_needed(self):
        users = self.db.list_users()
        if len(users) == 0:
            admin_email = BOOTSTRAP_ADMIN_EMAIL
            admin_pw = secrets.token_urlsafe(12)
            pwd_hash = CryptoUtils.hash_password(admin_pw)
            ok, err = self.db.create_user(admin_email, 'Administrator', pwd_hash, is_admin=True, is_enabled=True)
            if ok:
                logger.info('Bootstrapped admin: %s (password shown once to console)', admin_email)
                print('BOOTSTRAP ADMIN:')
                print('  email:', admin_email)
                print('  password:', admin_pw)
                try:
                    if ADMIN_EMAIL:
                        self.email.send(ADMIN_EMAIL, 'Bootstrap admin created', f'Admin: {admin_email}\\nPassword: {admin_pw}')
                except Exception as e:
                    logger.warning('Failed to email bootstrap admin info: %s', e)
    
    def initiate_action(self, email: str, action: str):
        if self.db.requests_in_window(email, RATE_LIMIT_WINDOW_MIN) >= RATE_LIMIT_MAX:
            self.db.log_event(email, action, 'RATE_LIMIT')
            raise RuntimeError(f'Rate limit exceeded: max {RATE_LIMIT_MAX} per {RATE_LIMIT_WINDOW_MIN} minutes')
        otp = CryptoUtils.gen_otp()
        salt, h = CryptoUtils.hash_otp_with_salt(otp)
        expires_at = (datetime.utcnow() + timedelta(seconds=OTP_TTL_SECONDS)).isoformat()
        self.db.store_otp(email, h, salt, expires_at)
        subject = f'Your OTP for USB {action.capitalize()}'
        body = f'Your one-time code to {action} USB ports is: {otp}\nThis code expires in {OTP_TTL_SECONDS//60} minutes.'
        self.email.send(email, subject, body)
        self.db.log_event(email, action, 'OTP_SENT', f'otp_ttl={OTP_TTL_SECONDS}s')
        return True
    
    def validate_and_execute(self, email: str, entered_otp: str, action: str):
        rec = self.db.get_otp(email)
        if not rec:
            self.db.log_event(email, action, 'NO_OTP')
            return False, 'No OTP found or it expired. Request a new one.'
        
        otp_id, otp_hash, salt, expires_at, attempts = rec
        expires_dt = datetime.fromisoformat(expires_at)
        
        if datetime.utcnow() > expires_dt:
            self.db.remove_otp(email)
            self.db.log_event(email, action, 'OTP_EXPIRED')
            return False, 'OTP expired. Request a new one.'
        
        h_calc = hashlib.sha256((salt + entered_otp).encode('utf-8')).hexdigest()
        
        if h_calc != otp_hash:
            attempts_after = self.db.increment_otp_attempts(otp_id)
            self.db.log_event(email, action, 'OTP_FAIL', f'attempts={attempts_after}')
            
            print(f"[DEBUG] OTP Failed - Attempts: {attempts_after}/{MAX_ATTEMPTS}")
            
            if attempts_after >= MAX_ATTEMPTS:
                print("[DEBUG] Maximum attempts exceeded - Triggering intruder detection")
                
                # Capture intruder image
                img_captured = False
                img_path = None
                
                if self.intruder:
                    try:
                        img_captured, img_path = self.intruder.capture()
                        print(f"[DEBUG] Intruder capture: success={img_captured}, file={img_path}")
                        self.db.log_event(email, action, 'INTRUDER_CAPTURE', f'captured={img_captured}, file={img_path}')
                    except Exception as e:
                        print(f"[ERROR] Intruder capture failed: {e}")
                        self.db.log_event(email, action, 'INTRUDER_CAPTURE', f'FAILED: {str(e)}')
                else:
                    print("[DEBUG] No intruder detector available (OpenCV missing)")
                    self.db.log_event(email, action, 'INTRUDER_CAPTURE', 'NO_DETECTOR_AVAILABLE')
                
                # Remove OTP
                self.db.remove_otp(email)
                
                # Send intruder alert email
                if ADMIN_EMAIL:
                    try:
                        print(f"[DEBUG] Sending intruder alert to: {ADMIN_EMAIL}")
                        
                        subject = 'INTRUDER ALERT: USB Security System'
                        body = f"""
    SECURITY BREACH DETECTED!

    An intruder has been detected attempting to access the USB security system.

    Details:
    - User Email: {email}
    - Action Attempted: {action.upper()}
    - Failed Attempts: {attempts_after}
    - Timestamp: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}
    - IP/Location: [System Local]

    {'Image captured and attached.' if img_captured else 'No image capture available.'}

    Please investigate immediately.

    USB Physical Security System
    """
                        
                        attachments = [img_path] if img_captured and img_path else None
                        self.email.send(ADMIN_EMAIL, subject, body, attachments)
                        
                        print("[DEBUG] Intruder alert email sent successfully")
                        self.db.log_event(ADMIN_EMAIL, 'INTRUDER_EMAIL', 'SENT', f'to={ADMIN_EMAIL}')
                        
                    except Exception as e:
                        print(f"[ERROR] Failed to send intruder alert email: {e}")
                        self.db.log_event(ADMIN_EMAIL, 'INTRUDER_EMAIL', 'FAILED', str(e))
                else:
                    print("[WARNING] No ADMIN_EMAIL configured - intruder alert not sent")
                    self.db.log_event(email, 'INTRUDER_EMAIL', 'NO_ADMIN_EMAIL')
                
                return False, f'SECURITY BREACH: Maximum attempts exceeded. Administrator has been notified. Image captured: {img_path or "No"}'
            
            return False, f'Invalid OTP. Attempts left: {MAX_ATTEMPTS - attempts_after}'
        
        # OTP correct - proceed with USB action
        try:
            if action == 'disable':
                USBController.run_block_script()
            else:
                USBController.run_unblock_script()
            self.db.remove_otp(email)
            self.db.log_event(email, action, 'SUCCESS')
            return True, f'USB {action}d successfully.'
        except PermissionError as pe:
            self.db.log_event(email, action, 'ERROR', str(pe))
            return False, str(pe)
        except Exception as e:
            self.db.log_event(email, action, 'ERROR', str(e))
            return False, f'Failed to {action} USB: {e}'


# ---------------- Modern UI Components ----------------
def create_styled_button(parent, text, command=None, bg_color=RED_ACCENT, fg_color=WHITE_TEXT, width=20, height=2):
    """Create a styled button with modern appearance"""
    btn = tk.Button(parent, text=text, command=command, 
                   bg=bg_color, fg=fg_color, font=('Segoe UI', 12, 'bold'),
                   width=width, height=height, relief='flat', bd=0,
                   activebackground='#b91c1c', activeforeground=WHITE_TEXT,
                   cursor='hand2')
    return btn

def create_styled_entry(parent, placeholder="", show=None, width=25):
    """Create a styled entry with modern appearance"""
    entry = tk.Entry(parent, font=('Segoe UI', 11), width=width, 
                    bg=LIGHT_BG, fg=WHITE_TEXT, insertbackground=WHITE_TEXT,
                    relief='flat', bd=5, show=show)
    return entry

def show_toast(parent, message, duration=3000):
    """Show a toast notification"""
    toast = tk.Toplevel(parent)
    toast.wm_overrideredirect(True)
    toast.configure(bg=DARK_BG)
    
    # Position at top right
    x = parent.winfo_rootx() + parent.winfo_width() - 300
    y = parent.winfo_rooty() + 50
    toast.geometry(f"280x60+{x}+{y}")
    
    label = tk.Label(toast, text=message, bg=DARK_BG, fg=WHITE_TEXT,
                    font=('Segoe UI', 10), wraplength=260, justify='center')
    label.pack(expand=True, fill='both', padx=10, pady=10)
    
    toast.after(duration, toast.destroy)

# ---------------- Modern Login UI ----------------
class ModernLoginUI:
    def __init__(self, root, core: AppCore, db: DBService):
        if not tk:
            raise RuntimeError('Tkinter not available')
        self.root = root
        self.core = core
        self.db = db
        
        self.setup_window()
        self.create_login_interface()
        self.center_window()
    
    def setup_window(self):
        self.root.title('USB Physical Security - Login')
        self.root.geometry('900x650')
        self.root.configure(bg=DARK_BG)
        self.root.resizable(False, False)
    
    def create_login_interface(self):
        # Main container
        main_frame = tk.Frame(self.root, bg=DARK_BG)
        main_frame.pack(fill='both', expand=True)
        
        # Left side - Branding
        left_frame = tk.Frame(main_frame, bg=DARK_BG, width=400)
        left_frame.pack(side='left', fill='both', expand=True, padx=20, pady=40)
        left_frame.pack_propagate(False)
        
        brand_label = tk.Label(left_frame, text='USB PHYSICAL\nSECURITY', 
                              bg=DARK_BG, fg=WHITE_TEXT,
                              font=('Segoe UI', 28, 'bold'), justify='center')
        brand_label.pack(pady=(60, 20))
        
        subtitle_label = tk.Label(left_frame, text='Secure Access Control System', 
                                 bg=DARK_BG, fg=GRAY_TEXT,
                                 font=('Segoe UI', 14))
        subtitle_label.pack(pady=(0, 40))
        
        icon_frame = tk.Frame(left_frame, bg=LIGHT_BG, width=120, height=120)
        icon_frame.pack(pady=20)
        icon_frame.pack_propagate(False)
        
        icon_label = tk.Label(icon_frame, text='🔒', bg=LIGHT_BG, fg=RED_ACCENT,
                             font=('Arial', 48))
        icon_label.pack(expand=True)
        
        # Right side - Login form
        right_frame = tk.Frame(main_frame, bg=LIGHT_BG, width=400)
        right_frame.pack(side='right', fill='both', expand=True, padx=20, pady=40)
        right_frame.pack_propagate(False)
        
        # Login form container (expanded fully)
        form_frame = tk.Frame(right_frame, bg=LIGHT_BG)
        form_frame.pack(expand=True, fill="both")
        
        # Welcome text
        welcome_label = tk.Label(form_frame, text='WELCOME', 
                                bg=LIGHT_BG, fg=WHITE_TEXT,
                                font=('Segoe UI', 24, 'bold'))
        welcome_label.pack(pady=(40, 10))
        
        signin_label = tk.Label(form_frame, text='Sign in to your account', 
                               bg=LIGHT_BG, fg=GRAY_TEXT,
                               font=('Segoe UI', 12))
        signin_label.pack(pady=(0, 40))
        
        # Email field
        email_label = tk.Label(form_frame, text='Email Address', 
                            bg=LIGHT_BG, fg=WHITE_TEXT,
                            font=('Segoe UI', 11, 'bold'))
        email_label.pack(anchor='w', padx=40)

        self.email_entry = tk.Entry(form_frame, font=('Segoe UI', 11), width=30, 
                                bg='white', fg='black', insertbackground='black',
                                relief='flat', bd=5)
        self.email_entry.pack(pady=(5, 20), padx=40, fill='x')
        
        # Password field
        password_label = tk.Label(form_frame, text='Password', 
                                bg=LIGHT_BG, fg=WHITE_TEXT,
                                font=('Segoe UI', 11, 'bold'))
        password_label.pack(anchor='w', padx=40)

        self.password_entry = tk.Entry(form_frame, font=('Segoe UI', 11), width=30, 
                                    bg='white', fg='black', insertbackground='black',
                                    relief='flat', bd=5, show='*')
        self.password_entry.pack(pady=(5, 10), padx=40, fill='x')
        
        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_password_cb = tk.Checkbutton(form_frame, text='Show Password',
                                         variable=self.show_password_var,
                                         command=self.toggle_password,
                                         bg=LIGHT_BG, fg=GRAY_TEXT,
                                         selectcolor=LIGHT_BG,
                                         activebackground=LIGHT_BG,
                                         font=('Segoe UI', 10))
        show_password_cb.pack(anchor='w', padx=40, pady=(0, 20))
        
        # Status label
        self.status_label = tk.Label(form_frame, text='', 
                                    bg=LIGHT_BG, fg=ERROR_RED,
                                    font=('Segoe UI', 10))
        self.status_label.pack(pady=(0, 20))
        
        # Login button
        login_btn = create_styled_button(form_frame, 'LOGIN', 
                                        command=self.on_login,
                                        width=25, height=2)
        login_btn.pack(pady=(10, 10), padx=40, fill='x')
        
        # Forgot password link (white with hover effect)
        forgot_btn = tk.Label(form_frame, text="Forgot Password?",
                             bg=LIGHT_BG, fg="white",
                             font=('Segoe UI', 10, 'underline'),
                             cursor="hand2")
        forgot_btn.pack(pady=(0, 30), anchor="center")

        # Bind click + hover effect
        forgot_btn.bind("<Button-1>", lambda e: self.on_forgot_password())
        forgot_btn.bind("<Enter>", lambda e: forgot_btn.config(fg=RED_ACCENT))
        forgot_btn.bind("<Leave>", lambda e: forgot_btn.config(fg="white"))
        
        # Bind keys
        self.root.bind('<Return>', lambda e: self.on_login())
        self.root.bind('<Escape>', lambda e: self.root.destroy())
    
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def toggle_password(self):
        if self.show_password_var.get():
            self.password_entry.config(show='')
        else:
            self.password_entry.config(show='*')
    
    def on_login(self):
        email = self.email_entry.get().strip().lower()
        pw = self.password_entry.get()
        
        if not email or not pw:
            self.status_label.config(text='Please enter email and password')
            return
        
        user = self.db.get_user(email)
        if not user:
            self.status_label.config(text='Invalid credentials')
            return
        
        _, _, name, pwd_hash, is_admin, is_enabled, _ = user
        
        if not is_enabled:
            self.status_label.config(text='Account is disabled. Contact administrator.')
            self.db.log_event(email, 'LOGIN', 'DISABLED')
            return
        
        if CryptoUtils.verify_password(pwd_hash, pw):
            self.db.log_event(email, 'LOGIN', 'SUCCESS')
            self.root.destroy()
            
            main_root = tk.Tk()
            current_user = {'email': email, 'name': name, 'is_admin': bool(is_admin)}
            ModernMainUI(main_root, current_user, self.core, self.db, on_logout=self.restart_login)
            main_root.mainloop()
        else:
            self.db.log_event(email, 'LOGIN', 'FAIL')
            self.status_label.config(text='Invalid credentials')
    
    def on_forgot_password(self):
        email = simpledialog.askstring('Forgot Password', 'Enter your account email:', parent=self.root)
        if not email:
            return
        
        email = email.strip().lower()
        u = self.db.get_user(email)
        if not u:
            show_toast(self.root, 'If the account exists, a temporary password has been sent.')
            return
        
        temp_pw = secrets.token_urlsafe(8)
        h = CryptoUtils.hash_password(temp_pw)
        self.db.update_user_password(email, h)
        
        try:
            self.core.email.send(email, 'Password reset - Temporary password', f'A temporary password: {temp_pw}\nPlease change after login.')
            self.db.log_event(email, 'PASSWORD_RESET', 'SENT')
            show_toast(self.root, 'Temporary password sent to your email.')
        except Exception as e:
            self.db.log_event(email, 'PASSWORD_RESET', 'FAILED', str(e))
            show_toast(self.root, f'Could not send email: {e}')
    
    def restart_login(self):
        show_login(self.core, self.db)


# ---------------- Modern Main UI ----------------
class ModernMainUI:
    def __init__(self, root, current_user, core: AppCore, db: DBService, on_logout=None):
        self.root = root
        self.core = core
        self.db = db
        self.current_user = current_user
        self.on_logout = on_logout
        self.admin_panel = None
        
        self.setup_window()
        self.create_main_interface()
        self.center_window()
    
    def setup_window(self):
        self.root.title('USB Physical Security For Systems')
        self.root.geometry('1000x650')
        self.root.configure(bg='black')
        self.root.resizable(False, False)
    
    def create_main_interface(self):
        # Top user bar
        userbar = tk.Frame(self.root, bg='black')
        userbar.pack(side='top', fill='x', padx=10, pady=(8, 0))
        
        # Username on the left
        username_text = self.current_user.get('name') or self.current_user.get('email')
        username_label = tk.Label(userbar, text=username_text,
                                 bg='black', fg='white',
                                 font=('Segoe UI', 11, 'bold'))
        username_label.pack(side='left')
        
        # Admin indicator
        if self.current_user.get('is_admin'):
            admin_label = tk.Label(userbar, text='(Admin)',
                                  bg='black', fg='#888888',
                                  font=('Segoe UI', 10, 'italic'))
            admin_label.pack(side='left', padx=(10, 0))
        
        # Buttons on the right
        logout_btn = tk.Button(userbar, text='Logout',
                              bg='#444444', fg='white',
                              font=('Segoe UI', 10, 'bold'),
                              relief='flat', bd=0,
                              command=self.handle_logout,
                              cursor='hand2')
        logout_btn.pack(side='right', padx=(8, 0))
        
        # Admin Panel button (only for admins)
        if self.current_user.get('is_admin'):
            admin_panel_btn = tk.Button(userbar, text='Admin Panel',
                                       bg='#333333', fg='white',
                                       font=('Segoe UI', 10, 'bold'),
                                       relief='flat', bd=0,
                                       command=self.open_admin_panel,
                                       cursor='hand2')
            admin_panel_btn.pack(side='right', padx=(8, 0))
        
        # Project Info ribbon
        ribbon = tk.Button(self.root, text='Project Info',
                   bg=RED_ACCENT, fg='white',
                   font=('Segoe UI', 12, 'bold'),
                   padx=12, pady=6,
                   relief='flat', bd=0,
                   activebackground='#b91c1c', cursor='hand2',
                   command=self.open_project_file)
        ribbon.place(relx=0.5, y=50, anchor='n')
        
        # Main title
        title = tk.Label(self.root, text='USB Physical Security!!!',
                        bg='black', fg='white',
                        font=('Segoe UI', 22, 'bold'))
        title.pack(pady=(100, 20))
        
        # USB Icon area
        self.create_usb_icon()
        
        # Control panel (gray box with red buttons)
        control_frame = tk.Frame(self.root, bg='#666666', width=420, height=240)
        control_frame.pack(pady=20)
        control_frame.pack_propagate(False)
        
        # Disable USB button
        disable_btn = tk.Button(control_frame, text='Disable USB',
                               bg=RED_ACCENT, fg='white',
                               font=('Segoe UI', 16, 'bold'),
                               width=20, height=2,
                               relief='flat', bd=0,
                               activebackground='#b91c1c',
                               command=lambda: self.user_action_flow('disable'),
                               cursor='hand2')
        disable_btn.pack(pady=(30, 10))
        
        # Enable USB button
        enable_btn = tk.Button(control_frame, text='Enable USB',
                              bg=RED_ACCENT, fg='white',
                              font=('Segoe UI', 16, 'bold'),
                              width=20, height=2,
                              relief='flat', bd=0,
                              activebackground='#b91c1c',
                              command=lambda: self.user_action_flow('enable'),
                              cursor='hand2')
        enable_btn.pack(pady=(10, 30))
        
        # Footer
        footer = tk.Label(self.root, text='© USB Physical Security',
                         bg='black', fg='white',
                         font=('Segoe UI', 9))
        footer.pack(side='bottom', pady=12)
        
        # Keyboard shortcuts
        self.root.bind_all('<Control-l>', lambda e: self.handle_logout())
    def open_project_file(self):
        file_path = r"M:\Mourya\Projects\CYBER_SECURITY\usb-physical-security\Project Information.html"
        try:
            webbrowser.open_new_tab(f"file:///{file_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open file:\n{e}")

    def create_usb_icon(self):
        """Create USB icon area"""
        icon_frame = tk.Frame(self.root, bg='white', width=160, height=160)
        icon_frame.pack(pady=8)
        icon_frame.pack_propagate(False)
        
        # Try to load USB icon image, fallback to drawn icon
        if PIL_AVAILABLE and os.path.exists('usb_icon.jpg'):
            try:
                img = Image.open('usb_icon.jpg').resize((160, 160))
                self.usb_photo = ImageTk.PhotoImage(img)
                icon_label = tk.Label(icon_frame, image=self.usb_photo, bg='white')
                icon_label.pack(fill='both', expand=True)
                return
            except Exception:
                pass
        
        # Fallback: draw USB icons
        canvas = tk.Canvas(icon_frame, width=160, height=160, bg='white', highlightthickness=0)
        canvas.pack(fill='both', expand=True)
        
        # Draw two USB connectors
        # Left USB (enabled - green check)
        canvas.create_rectangle(30, 60, 70, 100, fill='#333333', outline='#000000', width=2)
        canvas.create_rectangle(35, 65, 65, 75, fill='#666666')
        canvas.create_oval(45, 105, 65, 125, fill='#16a34a', outline='#ffffff', width=2)
        canvas.create_text(55, 115, text='✓', fill='white', font=('Arial', 12, 'bold'))
        
        # Right USB (disabled - red X)
        canvas.create_rectangle(90, 60, 130, 100, fill='#333333', outline='#000000', width=2)
        canvas.create_rectangle(95, 65, 125, 75, fill='#666666')
        canvas.create_oval(105, 105, 125, 125, fill='#dc2626', outline='#ffffff', width=2)
        canvas.create_text(115, 115, text='✗', fill='white', font=('Arial', 12, 'bold'))
    
    def center_window(self):
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def open_admin_panel(self):
        if self.admin_panel is None or not self.admin_panel.win.winfo_exists():
            self.admin_panel = ModernAdminPanel(self.root, self.current_user['email'], self.db, self.core)
        else:
            self.admin_panel.win.lift()
            self.admin_panel.win.focus_set()

    
    def user_action_flow(self, action):
        email = self.current_user.get('email')
        if not email:
            show_toast(self.root, 'No user email found')
            return
        
        try:
            self.core.initiate_action(email, action)
            self.show_otp_dialog(email, action)
        except Exception as e:
            show_toast(self.root, f'Could not send OTP: {e}')
    
    def show_otp_dialog(self, email, action):
        dialog = tk.Toplevel(self.root)
        dialog.title('Enter OTP')
        dialog.geometry('450x500')  # Increased height
        dialog.configure(bg=LIGHT_BG)
        dialog.resizable(False, False)

        # Center on screen
        dialog.transient(self.root)
        dialog.grab_set()
        x = (self.root.winfo_x() + (self.root.winfo_width() // 2)) - 225
        y = (self.root.winfo_y() + (self.root.winfo_height() // 2)) - 250
        dialog.geometry(f'450x500+{x}+{y}')

        # ==== Split into top (content) and bottom (buttons) ====
        top_frame = tk.Frame(dialog, bg=LIGHT_BG)
        top_frame.pack(fill='both', expand=True, padx=30, pady=20)

        bottom_frame = tk.Frame(dialog, bg=LIGHT_BG)
        bottom_frame.pack(side='bottom', pady=20)  # anchored at bottom

        # ----- Content in top_frame -----
        tk.Label(top_frame, text='OTP Verification',
                bg=LIGHT_BG, fg=WHITE_TEXT,
                font=('Segoe UI', 16, 'bold')).pack(pady=(0, 20))

        tk.Label(top_frame, text='Enter OTP sent to:',
                bg=LIGHT_BG, fg=GRAY_TEXT,
                font=('Segoe UI', 11)).pack()

        tk.Label(top_frame, text=email,
                bg=LIGHT_BG, fg=WHITE_TEXT,
                font=('Segoe UI', 12, 'bold')).pack(pady=(5, 20))

        tk.Label(top_frame, text='Enter 6-digit OTP:',
                bg=LIGHT_BG, fg=WHITE_TEXT,
                font=('Segoe UI', 11)).pack(anchor='w')

        otp_var = tk.StringVar()
        def limit_otp_len(*args):
            v = otp_var.get()
            if not v.isdigit():
                otp_var.set(''.join(filter(str.isdigit, v)))
            elif len(v) > 6:
                otp_var.set(v[:6])
        otp_var.trace_add("write", limit_otp_len)

        otp_entry = tk.Entry(top_frame, font=('Segoe UI', 16), width=15,
                            textvariable=otp_var,
                            bg='white', fg='black', insertbackground='black',
                            relief='solid', bd=2, justify='center')
        otp_entry.pack(pady=(10, 15), ipady=8)
        otp_entry.focus()

        attempts_info = tk.Label(top_frame, text=f"Attempts left: {MAX_ATTEMPTS}",
                                bg=LIGHT_BG, fg=GRAY_TEXT,
                                font=('Segoe UI', 10))
        attempts_info.pack(pady=(0, 10))

        status_label = tk.Label(top_frame, text='',
                                bg=LIGHT_BG, fg=ERROR_RED,
                                font=('Segoe UI', 10), wraplength=350)
        status_label.pack(pady=(0, 10))

        # ===== Handlers =====
        def on_submit():
            otp_value = otp_entry.get().strip()
            if not otp_value:
                status_label.config(text='Please enter the OTP', fg=ERROR_RED)
                return
            if len(otp_value) != 6 or not otp_value.isdigit():
                status_label.config(text='Please enter a valid 6-digit OTP', fg=ERROR_RED)
                return

            ok_status, msg = self.core.validate_and_execute(email, otp_value, action)
            if ok_status:
                show_toast(self.root, msg)
                dialog.destroy()
            else:
                status_label.config(text=msg, fg=ERROR_RED)
                if "Attempts left" in msg:
                    attempts_info.config(text=msg.split("Invalid OTP. ")[-1])
                elif "SECURITY BREACH" in msg:
                    attempts_info.config(text="❌ Security breach detected")
                    status_label.config(fg="red")
                    dialog.after(2000, dialog.destroy)

        def on_resend():
            try:
                self.core.initiate_action(email, action)
                status_label.config(text='New OTP sent to your email', fg=SUCCESS_GREEN)
                otp_entry.delete(0, 'end')
            except Exception as e:
                status_label.config(text=f'Error sending OTP: {e}', fg=ERROR_RED)

        # ===== Timer =====
        remaining_time = OTP_TTL_SECONDS
        def update_timer():
            nonlocal remaining_time
            if remaining_time > 0:
                m, s = divmod(remaining_time, 60)
                text = f"Time remaining: {m:02d}:{s:02d}"
                if not hasattr(update_timer, 'lbl'):
                    update_timer.lbl = tk.Label(top_frame, text=text,
                                                bg=LIGHT_BG, fg=GRAY_TEXT,
                                                font=('Segoe UI', 9))
                    update_timer.lbl.pack()
                else:
                    update_timer.lbl.config(text=text)
                remaining_time -= 1
                dialog.after(1000, update_timer)
            else:
                update_timer.lbl.config(text="OTP expired", fg=ERROR_RED)
        update_timer()

        # ===== Buttons in bottom_frame (centered) =====
        tk.Button(bottom_frame, text='SUBMIT', command=on_submit,
                bg=RED_ACCENT, fg=WHITE_TEXT,
                font=('Segoe UI', 12, 'bold'),
                width=12, height=2, relief='flat', bd=0).pack(side='left', padx=10)

        tk.Button(bottom_frame, text='RESEND', command=on_resend,
                bg='#4a5568', fg=WHITE_TEXT,
                font=('Segoe UI', 12, 'bold'),
                width=12, height=2, relief='flat', bd=0).pack(side='left', padx=10)

        tk.Button(bottom_frame, text='CANCEL', command=dialog.destroy,
                bg='#666666', fg=WHITE_TEXT,
                font=('Segoe UI', 12, 'bold'),
                width=12, height=2, relief='flat', bd=0).pack(side='left', padx=10)

        # Key bindings
        dialog.bind('<Return>', lambda e: on_submit())
        dialog.bind('<Escape>', lambda e: dialog.destroy())



    
    def handle_logout(self):
        if messagebox.askyesno('Logout', 'Are you sure you want to logout?'):
            self.root.destroy()
            if self.on_logout:
                self.on_logout()

# ---------------- Modern Admin Panel ----------------
class ModernAdminPanel:
    def __init__(self, master, admin_email, db: DBService, core: AppCore):
        self.admin_email = admin_email
        self.db = db
        self.core = core
        
        self.win = tk.Toplevel(master)
        self.win.title('Admin Panel')
        self.win.geometry('900x650')
        self.win.configure(bg=LIGHT_BG)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.win)
        self.notebook.pack(fill='both', expand=True, padx=10, pady=10)
        
        self.create_users_tab()
        self.create_logs_tab()
        self.create_captures_tab()
        self.create_controls_tab()
        
        self.refresh_all_data()
    
    def create_users_tab(self):
        """Create user management tab"""
        users_frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(users_frame, text='Users')
        
        # User creation section
        create_frame = ttk.LabelFrame(users_frame, text='Create New User', padding=10)
        create_frame.pack(fill='x', pady=(0, 20))
        
        ttk.Label(create_frame, text='Email:').grid(row=0, column=0, sticky='w', pady=5)
        self.reg_email = ttk.Entry(create_frame, width=40)
        self.reg_email.grid(row=0, column=1, columnspan=2, pady=5, padx=(10, 0), sticky='ew')
        
        ttk.Label(create_frame, text='Name:').grid(row=1, column=0, sticky='w', pady=5)
        self.reg_name = ttk.Entry(create_frame, width=40)
        self.reg_name.grid(row=1, column=1, columnspan=2, pady=5, padx=(10, 0), sticky='ew')
        
        self.is_admin_var = tk.IntVar()
        ttk.Checkbutton(create_frame, text='Administrator', variable=self.is_admin_var).grid(row=2, column=0, sticky='w', pady=5)
        
        self.is_enabled_var = tk.IntVar(value=1)
        ttk.Checkbutton(create_frame, text='Enabled', variable=self.is_enabled_var).grid(row=2, column=1, sticky='w', pady=5)
        
        ttk.Button(create_frame, text='Create User', command=self.create_user).grid(row=3, column=0, columnspan=3, pady=15)
        
        # User list section
        list_frame = ttk.LabelFrame(users_frame, text='Existing Users', padding=10)
        list_frame.pack(fill='both', expand=True)
        
        # User list with treeview
        columns = ('Email', 'Name', 'Admin', 'Enabled', 'Created')
        self.user_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=12)
        
        for col in columns:
            self.user_tree.heading(col, text=col)
            self.user_tree.column(col, width=150)
        
        self.user_tree.pack(fill='both', expand=True, pady=(0, 10))
        
        # User action buttons
        user_btn_frame = ttk.Frame(list_frame)
        user_btn_frame.pack(fill='x')
        
        ttk.Button(user_btn_frame, text='Refresh', command=self.refresh_users).pack(side='left', padx=(0, 10))
        ttk.Button(user_btn_frame, text='Toggle USB Enabled', command=self.toggle_user_enabled).pack(side='left', padx=(0, 10))
        ttk.Button(user_btn_frame, text='Toggle Admin', command=self.toggle_user_admin).pack(side='left', padx=(0, 10))
        ttk.Button(user_btn_frame, text='Delete User', command=self.delete_user).pack(side='left')
        ttk.Button(user_btn_frame, text='Reset Password', command=self.reset_user_password).pack(side='left')
    
    def create_logs_tab(self):
        """Create logs tab"""
        logs_frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(logs_frame, text='Logs')
        
        # Logs text area with scrollbar
        self.logs_text = ScrolledText(logs_frame, width=100, height=30, font=('Consolas', 9))
        self.logs_text.pack(fill='both', expand=True, pady=(0, 10))
        
        # Configure text tags for colored output
        self.logs_text.tag_config('SUCCESS', foreground='green')
        self.logs_text.tag_config('SENT', foreground='green')
        self.logs_text.tag_config('FAIL', foreground='red')
        self.logs_text.tag_config('ERROR', foreground='red')
        self.logs_text.tag_config('FAILED', foreground='red')
        
        ttk.Button(logs_frame, text='Refresh Logs', command=self.refresh_logs).pack()
    
    def create_captures_tab(self):
        """Create intruder captures tab"""
        captures_frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(captures_frame, text='Intruder Captures')
        
        self.captures_list = tk.Listbox(captures_frame, font=('Consolas', 10), height=25)
        self.captures_list.pack(fill='both', expand=True, pady=(0, 10))
        
        captures_btn_frame = ttk.Frame(captures_frame)
        captures_btn_frame.pack(fill='x')
        
        ttk.Button(captures_btn_frame, text='Refresh', command=self.refresh_captures).pack(side='left', padx=(0, 10))
        ttk.Button(captures_btn_frame, text='Open Selected', command=self.open_capture).pack(side='left')
    
    def create_controls_tab(self):
        """Create USB controls tab"""
        controls_frame = ttk.Frame(self.notebook, padding=20)
        self.notebook.add(controls_frame, text='USB Controls')
        
        ttk.Label(controls_frame, text='Direct USB Control (Administrator Mode)', 
                 font=('Segoe UI', 14, 'bold')).pack(pady=20)
        
        ttk.Button(controls_frame, text='Force Disable USB (Local)', 
                  command=self.force_disable_usb).pack(pady=10)
        ttk.Button(controls_frame, text='Force Enable USB (Local)', 
                  command=self.force_enable_usb).pack(pady=10)
        
        ttk.Label(controls_frame, text='Warning: These actions bypass OTP verification', 
                 foreground='red').pack(pady=20)
    
    def create_user(self):
        email = self.reg_email.get().strip().lower()
        name = self.reg_name.get().strip()
        is_admin = bool(self.is_admin_var.get())
        is_enabled = bool(self.is_enabled_var.get())
        
        if not email:
            messagebox.showerror('Error', 'Email is required')
            return
        
        temp_pw = secrets.token_urlsafe(10)
        pwd_hash = CryptoUtils.hash_password(temp_pw)
        
        ok, err = self.db.create_user(email, name or None, pwd_hash, is_admin=is_admin, is_enabled=is_enabled)
        
        if ok:
            try:
                self.core.email.send(email, 'Your account credentials', 
                                    f'Email: {email}\\nPassword: {temp_pw}\\nPlease change after first login.')
                self.db.log_event(email, 'EMAIL_CREDENTIALS', 'SENT')
            except Exception as e:
                self.db.log_event(email, 'EMAIL_CREDENTIALS', 'FAILED', str(e))
            
            messagebox.showinfo('Success', f'User created. Credentials emailed to {email}')
            self.clear_user_form()
            self.refresh_users()
        else:
            messagebox.showerror('Error', err)
    
    def clear_user_form(self):
        self.reg_email.delete(0, 'end')
        self.reg_name.delete(0, 'end')
        self.is_admin_var.set(0)
        self.is_enabled_var.set(1)
    
    def refresh_users(self):
        # Clear existing items
        for item in self.user_tree.get_children():
            self.user_tree.delete(item)
        
        # Load users
        users = self.db.list_users()
        for email, name, is_admin, is_enabled, created_at in users:
            self.user_tree.insert('', 'end', values=(
                email, name or '-', 
                'Yes' if is_admin else 'No',
                'Yes' if is_enabled else 'No',
                created_at[:10] if created_at else '-'
            ))
    
    def toggle_user_enabled(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Please select a user')
            return
        
        item = self.user_tree.item(selected[0])
        email = item['values'][0]
        current_enabled = item['values'][3] == 'Yes'
        
        self.db.set_user_enabled(email, not current_enabled)
        messagebox.showinfo('Success', f'User {email} {"disabled" if current_enabled else "enabled"}')
        self.refresh_users()
    
    def reset_user_password(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Please select a user')
            return
        
        item = self.user_tree.item(selected[0])
        email = item['values'][0]
        
        temp_pw = secrets.token_urlsafe(8)
        pwd_hash = CryptoUtils.hash_password(temp_pw)
        self.db.update_user_password(email, pwd_hash)
        
        try:
            self.core.email.send(email, 'Password Reset - Temporary Password', 
                                f'Your temporary password: {temp_pw}\\nPlease change after login.')
            self.db.log_event(email, 'PASSWORD_RESET', 'SENT')
            messagebox.showinfo('Success', 'Temporary password sent to user')
        except Exception as e:
            self.db.log_event(email, 'PASSWORD_RESET', 'FAILED', str(e))
            messagebox.showerror('Error', f'Could not send email: {e}')
    def toggle_user_admin(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Please select a user')
            return

        item = self.user_tree.item(selected[0])
        email = item['values'][0]
        current_admin = item['values'][2] == 'Yes'

        self.db.set_user_admin(email, not current_admin)
        messagebox.showinfo('Success', f'User {email} admin rights {"revoked" if current_admin else "granted"}')
        self.refresh_users()

    def delete_user(self):
        selected = self.user_tree.selection()
        if not selected:
            messagebox.showerror('Error', 'Please select a user')
            return

        item = self.user_tree.item(selected[0])
        email = item['values'][0]

        if messagebox.askyesno('Confirm Delete', f'Are you sure you want to delete user {email}?'):
            self.db.delete_user(email)
            self.db.log_event(self.admin_email, 'DELETE_USER', 'SUCCESS', f'user={email}')
            messagebox.showinfo('Deleted', f'User {email} deleted successfully')
            self.refresh_users()

    def refresh_logs(self):
        logs = self.db.get_logs(limit=500)
        self.logs_text.config(state='normal')
        self.logs_text.delete('1.0', 'end')
        
        for ts, email, action, status, details in logs:
            line = f"{ts} | {email} | {action} | {status} | {details}\n"
            
            # Apply color based on status
            tag = status.upper() if status.upper() in ['SUCCESS', 'SENT', 'FAIL', 'ERROR', 'FAILED'] else None
            self.logs_text.insert('end', line, tag)
        
        self.logs_text.config(state='disabled')
    
    def refresh_captures(self):
        files = [f for f in os.listdir('.') if f.startswith(INTRUDER_IMAGE_PREFIX)]
        self.captures_list.delete(0, 'end')
        
        for f in sorted(files, reverse=True):
            self.captures_list.insert('end', f)
    
    def open_capture(self):
        selection = self.captures_list.curselection()
        if not selection:
            return
        
        filename = self.captures_list.get(selection[0])
        try:
            if sys.platform.startswith('win'):
                os.startfile(filename)
            elif sys.platform.startswith('darwin'):
                subprocess.run(['open', filename])
            else:
                subprocess.run(['xdg-open', filename])
        except Exception as e:
            messagebox.showerror('Error', f'Could not open file: {e}')
    
    def force_disable_usb(self):
        try:
            USBController.run_block_script()
            messagebox.showinfo('Success', 'USB ports disabled via registry')
            self.db.log_event(self.admin_email, 'DISABLE_FORCE', 'SUCCESS')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.db.log_event(self.admin_email, 'DISABLE_FORCE', 'ERROR', str(e))
    
    def force_enable_usb(self):
        try:
            USBController.run_unblock_script()
            messagebox.showinfo('Success', 'USB ports enabled via registry')
            self.db.log_event(self.admin_email, 'ENABLE_FORCE', 'SUCCESS')
        except Exception as e:
            messagebox.showerror('Error', str(e))
            self.db.log_event(self.admin_email, 'ENABLE_FORCE', 'ERROR', str(e))
    
    def refresh_all_data(self):
        self.refresh_users()
        self.refresh_logs()
        self.refresh_captures()

# ---------------- Entry-point helpers ----------------
def show_login(core: AppCore, db: DBService):
    root = tk.Tk()
    ModernLoginUI(root, core, db)
    root.mainloop()

# ---------------- Main ----------------
def main():
    db = DBService()
    email_svc = EmailService()
    intr = IntruderDetector() if cv2 else None
    core = AppCore(db, email_svc, intr)
    
    core.bootstrap_admin_if_needed()
    
    if not tk:
        logger.info('Tkinter not available; running headless')
        return
    
    show_login(core, db)

if __name__ == '__main__':
    main()
