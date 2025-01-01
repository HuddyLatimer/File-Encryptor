
# Advanced Encryption System (

The Advanced Encryption System  is a Python-based file and folder encryption tool designed for ease of use and strong security. It provides a sleek graphical user interface (GUI), robust encryption/decryption functionality using the `cryptography` library, and password strength analysis to ensure secure operations.

## Features
- **File and Folder Encryption/Decryption:** Encrypt and decrypt files and folders with ease.
- **User-Friendly Interface:** Modern GUI powered by `Tkinter` and `ttkthemes`.
- **Operation Logs:** Detailed logs to track encryption and decryption operations.
- **Progress Monitoring:** Real-time progress bar for tracking the operation status.

## Installation
### Prerequisites
1. Python 3.8 or newer installed.
2. Required Python libraries:
   - `tkinter`
   - `cryptography`
   - `ttkthemes`

Install dependencies using pip:
```bash
pip install cryptography ttkthemes
```

### Running the Application
1. Clone the repository:
   ```bash
   git clone https://github.com/HuddyLatimer/File-Encryptor.git
   cd File-Encryptor
   ```
2. Run the script:
   ```bash
   python QuantumCipherGUI.py
   ```

## Usage
1. Launch the application.
2. Select a file or folder to encrypt/decrypt.
3. Enter a secure encryption key (password).
4. Click on the desired operation (Encrypt/Decrypt).
5. View progress and logs in the application.

## Screenshots
![image](https://github.com/user-attachments/assets/f8b4746a-6189-4599-af20-38bee857d551)



## Technical Details
- **Encryption Algorithm:** Uses `PBKDF2HMAC` for key derivation and `Fernet` for encryption.
- **File Compression:** Automatically compresses folders into `.zip` files for encryption.
- **Error Handling:** Comprehensive error handling with user-friendly feedback.

## Contributing
Contributions are welcome! Feel free to submit issues or pull requests to improve the application.

## Acknowledgments
- Built using Python and the `cryptography` library.
- GUI enhanced by `ttkthemes`.

## Disclaimer
This tool is intended for educational purposes. The developers are not responsible for any data loss or misuse.

