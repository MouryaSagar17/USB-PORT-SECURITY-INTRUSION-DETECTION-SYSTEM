import tkinter as tk
from tkinter import PhotoImage
from secure_usb_control import prompt_and_send
import webbrowser 
from PIL import Image, ImageTk
from tkinter import messagebox
import os
# CONFIG - change to your email
ADMIN_EMAIL = "mouryamourya289@gmail.com"

# === Button actions ===
def disable_usb():
    prompt_and_send(root, ADMIN_EMAIL, 'disable')

def enable_usb():
    prompt_and_send(root, ADMIN_EMAIL, 'enable')

def show_info():
    # Put your full PDF file path here
    pdf_path = r"M:\Mourya\Projects\CYBER_SECURITY\USB_CONTROL\B.Tech-CSE-Cyber Security-R20.pdf"

    if os.path.exists(pdf_path):
        os.startfile(pdf_path)  # Works on Windows to open in default viewer
        print(f"[INFO] Opening PDF report: {pdf_path}")
    else:
        print(f"[ERROR] PDF file not found: {pdf_path}")

# === Main window ===
root = tk.Tk()
root.title("USB Physical Security For Systems")
root.geometry("400x500")
root.configure(bg="black")

# === Top Project Info button ===
btn_info = tk.Button(root, text="Project Info", bg="red", fg="white", font=("Arial", 12, "bold"),
                     command=show_info)
btn_info.pack(pady=10)

# === Title ===
lbl_title = tk.Label(root, text="USB Physical Security!!!", font=("Arial", 16, "bold"), bg="black", fg="white")
lbl_title.pack(pady=10)

# === Center Image ===
try:
    pil_img = Image.open("usb_icon.jpg")  # Supports JPG/PNG/etc.
    pil_img = pil_img.resize((100, 100))  # Resize if needed
    img = ImageTk.PhotoImage(pil_img)
except Exception:
    img = None

if img:
    img_label = tk.Label(root, image=img, bg="black")
    img_label.image = img  # Prevent garbage collection
    img_label.pack(pady=10)
else:
    tk.Label(root, text="[Image Missing]", bg="black", fg="white").pack(pady=10)

# === Grey box with buttons ===
frame_buttons = tk.Frame(root, bg="grey", padx=20, pady=20)
frame_buttons.pack(pady=20)

btn_disable = tk.Button(frame_buttons, text="Disable USB", bg="red", fg="white",
                        font=("Arial", 12, "bold"), width=20, command=disable_usb)
btn_disable.pack(pady=10)

btn_enable = tk.Button(frame_buttons, text="Enable USB", bg="red", fg="white",
                       font=("Arial", 12, "bold"), width=20, command=enable_usb)
btn_enable.pack(pady=10)

root.mainloop()
