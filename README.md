# 🔒 SecureVault - Encrypted Data Storage System

SecureVault is a secure data storage application built with Python and Streamlit that provides military-grade encryption for your sensitive information. This application allows users to safely store and retrieve confidential data using a combination of strong authentication and encryption protocols.

## Key Features

- **User Authentication**: Secure PBKDF2 password hashing with salt
- **Data Encryption**: Fernet symmetric encryption for stored data
- **Brute Force Protection**: Account lockout after failed attempts
- **Passkey Security**: Separate encryption passkey for data access
- **Modern UI**: Clean, responsive interface with Streamlit

## Technical Implementation

- **Backend**: Python 3 with cryptography libraries
- **Frontend**: Streamlit for web interface
- **Security**:
  - PBKDF2-HMAC-SHA256 for password hashing (100,000 iterations)
  - Fernet (AES-128-CBC) for data encryption
  - Secure salt generation for all cryptographic operations
  - Session-based authentication

## How It Works

1. Users register with a username and strong password
2. Sensitive data is encrypted client-side before storage
3. Data can only be decrypted with the correct passkey
4. All operations are protected against brute force attacks

## Use Cases

- Personal password management
- Secure note storage
- Confidential document encryption
- Sensitive data archiving

## Requirements

- Python 3.8+
- Streamlit
- cryptography