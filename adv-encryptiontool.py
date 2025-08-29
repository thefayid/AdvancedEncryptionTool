import os
import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import secrets

# ---------------------------
# AES-256 Encryption/Decryption Tool (GUI)
# Developed by Fayid ❤️
# ---------------------------

def derive_key(password: str, salt: bytes) -> bytes:
    """Derive AES-256 key from password"""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256-bit key
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def encrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            data = f.read()

        salt = secrets.token_bytes(16)
        key = derive_key(password, salt)
        iv = secrets.token_bytes(16)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        encrypted_data = encryptor.update(data) + encryptor.finalize()

        encrypted_file = file_path + ".enc"
        with open(encrypted_file, "wb") as f:
            f.write(salt + iv + encrypted_data)

        messagebox.showinfo("Success", f"File encrypted successfully!\nSaved as: {encrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

def decrypt_file(file_path, password):
    try:
        with open(file_path, "rb") as f:
            file_data = f.read()

        salt, iv, encrypted_data = file_data[:16], file_data[16:32], file_data[32:]
        key = derive_key(password, salt)

        cipher = Cipher(algorithms.AES(key), modes.CFB(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        decrypted_data = decryptor.update(encrypted_data) + decryptor.finalize()

        decrypted_file = file_path.replace(".enc", "_decrypted")
        with open(decrypted_file, "wb") as f:
            f.write(decrypted_data)

        messagebox.showinfo("Success", f"File decrypted successfully!\nSaved as: {decrypted_file}")
    except Exception as e:
        messagebox.showerror("Error", str(e))

# ---------------------------
# Tkinter GUI
# ---------------------------
def select_file_encrypt():
    file_path = filedialog.askopenfilename()
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        encrypt_file(file_path, password)

def select_file_decrypt():
    file_path = filedialog.askopenfilename(filetypes=[("Encrypted files", "*.enc")])
    if file_path:
        password = password_entry.get()
        if not password:
            messagebox.showwarning("Warning", "Please enter a password.")
            return
        decrypt_file(file_path, password)

# Main window
root = tk.Tk()
root.title("🔐 Advanced AES-256 Encryption Tool - Developed by Fayid ❤️")
root.geometry("500x300")
root.resizable(False, False)

# UI Elements
tk.Label(root, text="Advanced AES-256 Encryption Tool", font=("Arial", 14, "bold")).pack(pady=10)
tk.Label(root, text="Developed by Fayid ❤️", font=("Arial", 10, "italic")).pack(pady=5)

tk.Label(root, text="Enter Password:", font=("Arial", 12)).pack(pady=5)
password_entry = tk.Entry(root, show="*", width=30, font=("Arial", 12))
password_entry.pack(pady=5)

encrypt_btn = tk.Button(root, text="🔒 Encrypt File", command=select_file_encrypt, bg="green", fg="white", font=("Arial", 12))
encrypt_btn.pack(pady=10)

decrypt_btn = tk.Button(root, text="🔓 Decrypt File", command=select_file_decrypt, bg="blue", fg="white", font=("Arial", 12))
decrypt_btn.pack(pady=10)

root.mainloop()
