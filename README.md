# USB Physical Security System 🔒

A Python-based USB port security application for Windows with:
- Modern Tkinter GUI (login + admin panel)
- OTP-based access control via email
- Intruder detection using webcam (OpenCV)
- SQLite database for users, OTPs, and logs
- USB enable/disable through Windows Registry (admin rights required)

---

## 🚀 Features
- User authentication with password hashing (bcrypt / SHA256 fallback)
- OTP verification with expiry, rate limits, and attempt limits
- Intruder capture via webcam after failed OTP attempts
- Email notifications for OTPs, password resets, and intruder alerts
- Admin panel for user management, logs, and direct USB control
- Modern UI built using Tkinter with styled components

---

## 📂 Project Structure
```
usb-control/
│
├── secure_usb_control.py  # Python project code 
├── requirements.txt     # Dependencies
├── README.md            # Documentation
└── .gitignore           # Ignore unnecessary files (like __pycache__)

```

---

## ⚙️ Requirements
- **Python 3.9+**
- Windows OS (for USB registry control)
- Admin privileges (to enable/disable USB ports)
- Internet connection (for email OTPs)

Install dependencies:
```bash
pip install -r requirements.txt
```

---

## 🔑 Environment Variables
Before running, configure SMTP details (example for Gmail):

**PowerShell (Windows):**
```powershell
setx SMTP_HOST "smtp.gmail.com"
setx SMTP_PORT "587"
setx SMTP_USER "your_email@gmail.com"
setx SMTP_PASS "your_app_password"
setx ADMIN_EMAIL "admin_email@gmail.com"
```

Restart terminal after setting them.

---

## ▶️ Running the Application
Run the main script:
```bash
python .\secure_usb_control.py
```

If no admin user exists, a bootstrap admin will be created and shown in the console.

---

## 📸 Intruder Detection
- If OTP attempts exceed the maximum limit, the app captures an image using your webcam (if OpenCV is available).  
- The image is stored locally and emailed to the configured admin.

---

## ⚠️ Notes
- Some features (like registry modification for USB control) **require Administrator privileges**.  
- Run Python or your IDE as **Administrator**.  
- Intruder capture requires a working webcam.  
- Works best with Gmail SMTP (use an **App Password**).

---

## 📝 License
This project is provided as-is for **educational and research purposes**.  
Use responsibly when deploying in real environments.

---

## 👨‍💻 Author
Developed for **Cyber Security Projects** (USB Physical Security System).

