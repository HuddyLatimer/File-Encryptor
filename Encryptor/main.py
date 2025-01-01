import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import os
import zipfile
import json
import random
import datetime
import threading
from ttkthemes import ThemedTk


class QuantumAI:
    def __init__(self):
        self.responses = {
            'greeting': [
                "Welcome to the Advanced Encryptor Tool!",
            ],
            'encrypting': [
                "Initiating quantum encryption protocols...",
                "Generating secure encryption matrix...",
                "Establishing encrypted data container..."
            ],
            'decrypting': [
                "Beginning decryption sequence...",
                "Analyzing encryption signature...",
                "Reconstructing original data structure..."
            ],
            'success': [
                "Operation completed successfully. Your data is secure.",
                "Security protocols executed successfully.",
                "Encryption matrix stable. Operation complete."
            ],
            'error': [
                "Alert: Security breach detected. Operation failed.",
                "Critical error in encryption matrix.",
                "Security protocols compromised. Please retry."
            ]
        }

    def respond(self, category):
        return random.choice(self.responses[category])

    def analyze_security(self, password):
        score = 0
        checks = {
            'length': len(password) >= 12,
            'uppercase': any(c.isupper() for c in password),
            'lowercase': any(c.islower() for c in password),
            'numbers': any(c.isdigit() for c in password),
            'special': any(not c.isalnum() for c in password)
        }

        score = sum(checks.values()) * 20

        if score < 60:
            return "Warning: Password strength insufficient. Recommend enhancement."
        elif score < 80:
            return "Password strength moderate. Consider additional complexity."
        else:
            return "Password strength optimal. Quantum encryption ready."


class QuantumCipherGUI:
    def __init__(self):
        self.root = ThemedTk(theme="equilux")
        self.root.title("Advanced Encryption System")
        self.root.geometry("800x600")

        # Add icon to the window
        try:
            self.root.iconbitmap('icon3.ico')
        except:
            print("Icon file 'icon3.ico' not found")

        self.ai = QuantumAI()
        self.setup_gui()
        self.log_history = []

    def setup_gui(self):
        # Main container
        self.main_frame = ttk.Frame(self.root, padding="10")
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        # AI Status Display
        self.ai_frame = ttk.LabelFrame(self.main_frame, text="Encryptor", padding="10")
        self.ai_frame.pack(fill=tk.X, pady=5)

        self.ai_status = tk.Text(self.ai_frame, height=3, wrap=tk.WORD, bg='black', fg='#00ff00')
        self.ai_status.pack(fill=tk.X)
        self.ai_status.insert('1.0', self.ai.respond('greeting'))
        self.ai_status.config(state='disabled')

        # Operation Frame
        self.op_frame = ttk.LabelFrame(self.main_frame, text="Operation Control", padding="10")
        self.op_frame.pack(fill=tk.X, pady=5)

        # File Selection
        ttk.Label(self.op_frame, text="Target:").pack(anchor=tk.W)
        self.file_frame = ttk.Frame(self.op_frame)
        self.file_frame.pack(fill=tk.X, pady=5)

        self.file_path = ttk.Entry(self.file_frame)
        self.file_path.pack(side=tk.LEFT, fill=tk.X, expand=True)

        ttk.Button(self.file_frame, text="Select File", command=self.select_file).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.file_frame, text="Select Folder", command=self.select_folder).pack(side=tk.LEFT)

        # Password Entry
        ttk.Label(self.op_frame, text="Encryption Key:").pack(anchor=tk.W)
        self.password = ttk.Entry(self.op_frame, show="●")
        self.password.pack(fill=tk.X, pady=5)

        # Operation Buttons
        self.btn_frame = ttk.Frame(self.op_frame)
        self.btn_frame.pack(fill=tk.X, pady=5)

        ttk.Button(self.btn_frame, text="Encrypt", command=self.encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(self.btn_frame, text="Decrypt", command=self.decrypt).pack(side=tk.LEFT)

        # Progress Frame
        self.progress_frame = ttk.LabelFrame(self.main_frame, text="Operation Progress", padding="10")
        self.progress_frame.pack(fill=tk.X, pady=5)

        self.progress = ttk.Progressbar(self.progress_frame, mode='determinate')
        self.progress.pack(fill=tk.X)

        # Log Display
        self.log_frame = ttk.LabelFrame(self.main_frame, text="Operation Log", padding="10")
        self.log_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        self.log_display = tk.Text(self.log_frame, height=10, wrap=tk.WORD, bg='black', fg='#00ff00')
        self.log_display.pack(fill=tk.BOTH, expand=True)

    def update_ai_status(self, message):
        self.ai_status.config(state='normal')
        self.ai_status.delete('1.0', tk.END)
        self.ai_status.insert('1.0', message)
        self.ai_status.config(state='disabled')
        self.root.update()

    def log_operation(self, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        log_entry = f"[{timestamp}] {message}\n"
        self.log_display.insert(tk.END, log_entry)
        self.log_display.see(tk.END)
        self.log_history.append(log_entry)

    def select_file(self):
        path = filedialog.askopenfilename()
        if path:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, path)

    def select_folder(self):
        path = filedialog.askdirectory()
        if path:
            self.file_path.delete(0, tk.END)
            self.file_path.insert(0, path)

    def get_encryption_key(self, password):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=b'quantum_salt_123',  # In production, use a random salt and store it
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_file(self, path, fernet):
        with open(path, 'rb') as file:
            data = file.read()
        encrypted_data = fernet.encrypt(data)
        with open(path + '.encrypted', 'wb') as file:
            file.write(encrypted_data)
        os.remove(path)

    def decrypt_file(self, path, fernet):
        with open(path, 'rb') as file:
            encrypted_data = file.read()
        decrypted_data = fernet.decrypt(encrypted_data)
        with open(path[:-10], 'wb') as file:
            file.write(decrypted_data)
        os.remove(path)

    def process_path(self, path, fernet, operation='encrypt'):
        if os.path.isfile(path):
            if operation == 'encrypt':
                self.encrypt_file(path, fernet)
            else:
                self.decrypt_file(path, fernet)
        else:
            if operation == 'encrypt':
                zip_path = path + '.zip'
                with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                    for root, _, files in os.walk(path):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, path)
                            zipf.write(file_path, arcname)
                self.encrypt_file(zip_path, fernet)
                os.remove(zip_path)
            else:
                decrypted_zip = path[:-10]
                self.decrypt_file(path, fernet)
                with zipfile.ZipFile(decrypted_zip, 'r') as zipf:
                    zipf.extractall(decrypted_zip[:-4])
                os.remove(decrypted_zip)

    def encrypt(self):
        path = self.file_path.get()
        password = self.password.get()

        if not path or not password:
            self.update_ai_status(self.ai.respond('error'))
            messagebox.showerror("Error", "Please provide both path and password")
            return

        self.update_ai_status(self.ai.respond('encrypting'))
        self.log_operation(f"Starting encryption of: {path}")

        try:
            key = self.get_encryption_key(password)
            fernet = Fernet(key)

            self.process_path(path, fernet, 'encrypt')

            self.update_ai_status(self.ai.respond('success'))
            self.log_operation("Encryption completed successfully")
            messagebox.showinfo("Success", "Encryption completed")

        except Exception as e:
            self.update_ai_status(self.ai.respond('error'))
            self.log_operation(f"Error during encryption: {str(e)}")
            messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt(self):
        path = self.file_path.get()
        password = self.password.get()

        if not path or not password:
            self.update_ai_status(self.ai.respond('error'))
            messagebox.showerror("Error", "Please provide both path and password")
            return

        self.update_ai_status(self.ai.respond('decrypting'))
        self.log_operation(f"Starting decryption of: {path}")

        try:
            key = self.get_encryption_key(password)
            fernet = Fernet(key)

            self.process_path(path, fernet, 'decrypt')

            self.update_ai_status(self.ai.respond('success'))
            self.log_operation("Decryption completed successfully")
            messagebox.showinfo("Success", "Decryption completed")

        except Exception as e:
            self.update_ai_status(self.ai.respond('error'))
            self.log_operation(f"Error during decryption: {str(e)}")
            messagebox.showerror("Error", f"Decryption failed: {str(e)}")


if __name__ == "__main__":
    app = QuantumCipherGUI()
    app.root.mainloop()