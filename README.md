# Password Vault

A secure password manager with a GUI built in Python. Store and manage your passwords safely with encryption.

## Features

- **User Authentication**: Create and login with your own account
- **Secure Encryption**: All passwords are encrypted using Fernet symmetric encryption
- **Easy-to-Use GUI**: Simple and intuitive interface built with Tkinter
- **Password Management**: Add, view, update, copy, and delete passwords
- **Site Organization**: Store passwords by site name for easy retrieval

## Installation

1. Install the required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python password_vault.py
```

2. **First Time Setup**:
   - Click "Register" to create a new account
   - Enter a username and master password (minimum 6 characters)
   - Your master password is used to encrypt all your saved passwords

3. **Login**:
   - Enter your username and master password
   - Click "Login"

4. **Adding Passwords**:
   - Enter the site name (e.g., "Gmail", "Facebook")
   - Enter the password for that site
   - Click "Add/Update"

5. **Viewing Passwords**:
   - Select a site from the list
   - Click "View Password" to see it in a popup
   - Click "Copy Password" to copy it to your clipboard
   - Click "Delete" to remove it from the vault

## Security Features

- Master passwords are hashed with SHA-256 and salted
- Site passwords are encrypted using Fernet (AES-128)
- Database stores only encrypted data
- Each user's data is isolated by user ID

## Files

- `password_vault.py` - Main GUI application
- `database.py` - Database operations and user management
- `encryption.py` - Password encryption and decryption
- `requirements.txt` - Python dependencies
- `password_vault.db` - SQLite database (created automatically)

## Requirements

- Python 3.7+
- cryptography 41.0.7
- tkinter (included with Python)

## Important Notes

- **Never forget your master password!** It cannot be recovered
- The encryption key is derived from your master password
- Keep your `password_vault.db` file secure
- Make regular backups of the database file