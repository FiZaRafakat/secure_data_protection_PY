import streamlit as st
import hashlib
import json
import os
import time
from cryptography.fernet import Fernet
import binascii
from datetime import datetime

# Custom CSS for styling
def local_css():
    st.markdown("""
    <style>
        .main {
            background-color: #f8f9fa;
        }
        .stTextInput input, .stTextArea textarea {
            border-radius: 8px;
            border: 1px solid #ced4da;
        }
        .stButton button {
            border-radius: 8px;
            border: none;
            background-color: #4e73df;
            color: white;
            padding: 8px 16px;
            font-weight: 500;
        }
        .stButton button:hover {
            background-color: #2e59d9;
        }
        .success-box {
            background-color: #d4edda;
            color: #155724;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .error-box {
            background-color: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .info-box {
            background-color: #d1ecf1;
            color: #0c5460;
            padding: 15px;
            border-radius: 8px;
            margin: 10px 0;
        }
        .sidebar .sidebar-content {
            background-color: #f8f9fa;
        }
        .logo {
            font-size: 24px;
            font-weight: 700;
            margin-bottom: 20px;
            color: #4e73df;
        }
    </style>
    """, unsafe_allow_html=True)

# Configuration
DATA_FILE = "secure_data.json"
USERS_FILE = "users.json"
MAX_FAILED_ATTEMPTS = 3
LOCKOUT_TIME = 300  # 5 minutes in seconds
PBKDF2_ITERATIONS = 100000

# Initialize session state
if 'authenticated' not in st.session_state:
    st.session_state.authenticated = False
if 'current_user' not in st.session_state:
    st.session_state.current_user = None
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = 0

# Generate or load encryption key
def get_encryption_key():
    key_file = "secret.key"
    if os.path.exists(key_file):
        with open(key_file, "rb") as f:
            key = f.read()
    else:
        key = Fernet.generate_key()
        with open(key_file, "wb") as f:
            f.write(key)
    return key

KEY = get_encryption_key()
cipher = Fernet(KEY)

# Load/save functions 
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, "r") as f:
            return json.load(f)
    return {}

def save_users(users):
    with open(USERS_FILE, "w") as f:
        json.dump(users, f)

# Security functions 
def hash_password(password, salt=None):
    if salt is None:
        salt = os.urandom(16)
    else:
        salt = binascii.unhexlify(salt)
    
    hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS)
    return binascii.hexlify(salt).decode(), binascii.hexlify(hashed).decode()

def verify_password(stored_salt, stored_hash, password):
    try:
        salt = binascii.unhexlify(stored_salt)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, PBKDF2_ITERATIONS)
        return binascii.hexlify(hashed).decode() == stored_hash
    except:
        return False


def is_locked_out():
    if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
        if time.time() - st.session_state.lockout_time < LOCKOUT_TIME:
            remaining_time = int(LOCKOUT_TIME - (time.time() - st.session_state.lockout_time))
            st.markdown(f'<div class="error-box">🔒 Account locked. Please try again in {remaining_time} seconds.</div>', unsafe_allow_html=True)
            return True
        else:
            st.session_state.failed_attempts = 0
    return False

def encrypt_data(text):
    return cipher.encrypt(text.encode()).decode()

def decrypt_data(encrypted_text):
    return cipher.decrypt(encrypted_text.encode()).decode()

# Enhanced UI Components
def show_success(message):
    st.markdown(f'<div class="success-box">✅ {message}</div>', unsafe_allow_html=True)

def show_error(message):
    st.markdown(f'<div class="error-box">❌ {message}</div>', unsafe_allow_html=True)

def show_info(message):
    st.markdown(f'<div class="info-box">ℹ️ {message}</div>', unsafe_allow_html=True)

# Auth Pages with Enhanced UI
def register_user():
    st.subheader("👤 Create Your Account")
    col1, col2 = st.columns(2)
    with col1:
        username = st.text_input("Username")
    with col2:
        password = st.text_input("Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    
    if st.button("Register", key="register_btn"):
        if not username or not password:
            show_error("Username and password are required!")
            return
        if password != confirm_password:
            show_error("Passwords don't match!")
            return
            
        users = load_users()
        if username in users:
            show_error("Username already exists!")
            return
            
        salt, hashed_password = hash_password(password)
        users[username] = {
            "salt": salt,
            "hashed_password": hashed_password,
            "created_at": str(datetime.now())
        }
        save_users(users)
        show_success("Registration successful! Please login.")
        time.sleep(1)
        st.rerun()

def login_user():
    st.subheader("🔑 Login to Your Account")
    username = st.text_input("Username", key="login_username")
    password = st.text_input("Password", type="password", key="login_password")
    
    if is_locked_out():
        return
        
    if st.button("Login", key="login_btn"):
        users = load_users()
        if username not in users:
            show_error("Invalid username or password!")
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                st.session_state.lockout_time = time.time()
            return
            
        user = users[username]
        if verify_password(user["salt"], user["hashed_password"], password):
            st.session_state.authenticated = True
            st.session_state.current_user = username
            st.session_state.failed_attempts = 0
            show_success("Login successful!")
            time.sleep(1)
            st.rerun()
        else:
            show_error("Invalid username or password!")
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                st.session_state.lockout_time = time.time()

def logout_user():
    st.session_state.authenticated = False
    st.session_state.current_user = None
    show_success("Logged out successfully!")
    time.sleep(1)
    st.rerun()

# Main App Pages with Enhanced UI
def store_data():
    st.subheader("🔐 Store Your Data Securely")
    show_info("Enter your sensitive data below. It will be encrypted and stored safely.")
    
    user_data = st.text_area("Your Data", height=150)
    passkey = st.text_input("Encryption Passkey", type="password", 
                           help="Create a strong passkey you'll remember")
    
    if st.button("Encrypt & Save", key="store_btn"):
        if not all([user_data, passkey]):
            show_error("Both data and passkey are required!")
            return
            
        data = load_data()
        user_key = st.session_state.current_user
        
        salt, hashed_passkey = hash_password(passkey)
        encrypted_text = encrypt_data(user_data)
        
        data[user_key] = {
            "encrypted_text": encrypted_text,
            "passkey_salt": salt,
            "passkey_hash": hashed_passkey,
            "created_at": str(datetime.now())
        }
        
        save_data(data)
        show_success("Data stored securely!")
        show_info("Remember your passkey - you'll need it to retrieve your data")

def retrieve_data():
    st.subheader("🔓 Retrieve Your Data")
    show_info("Enter your passkey to decrypt and view your stored data")
    
    passkey = st.text_input("Decryption Passkey", type="password", key="retrieve_passkey")
    
    if is_locked_out():
        return
        
    if st.button("Decrypt", key="retrieve_btn"):
        if not passkey:
            show_error("Passkey is required!")
            return
            
        data = load_data()
        user_key = st.session_state.current_user
        
        if user_key not in data:
            show_error("No data found for your account!")
            return
            
        stored_data = data[user_key]
        
        if verify_password(stored_data["passkey_salt"], stored_data["passkey_hash"], passkey):
            try:
                decrypted_text = decrypt_data(stored_data["encrypted_text"])
                st.session_state.failed_attempts = 0
                show_success("Data decrypted successfully!")
                st.text_area("Your Decrypted Data", value=decrypted_text, height=200)
            except:
                show_error("Decryption failed!")
                st.session_state.failed_attempts += 1
                if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                    st.session_state.lockout_time = time.time()
        else:
            show_error("Incorrect passkey!")
            st.session_state.failed_attempts += 1
            if st.session_state.failed_attempts >= MAX_FAILED_ATTEMPTS:
                st.session_state.lockout_time = time.time()

def home_page():
    st.subheader(f"👋 Welcome, {st.session_state.current_user}!")
    st.markdown("""
    <div style="background-color: #e9ecef; padding: 20px; border-radius: 10px;">
        <h4 style="color: #2c3e50;">Your Secure Data Vault</h4>
        <p>Store and retrieve your sensitive information with military-grade encryption.</p>
    </div>
    """, unsafe_allow_html=True)
    
    st.markdown("""
    ### How It Works
    
    <div style="display: flex; justify-content: space-between; margin: 20px 0;">
        <div style="flex: 1; padding: 15px; background: #f8f9fa; border-radius: 8px; margin: 0 5px; text-align: center;">
            <h5>1. Store Data</h5>
            <p>Encrypt your data with a passkey</p>
        </div>
        <div style="flex: 1; padding: 15px; background: #f8f9fa; border-radius: 8px; margin: 0 5px; text-align: center;">
            <h5>2. Secure Storage</h5>
            <p>Data is encrypted before storage</p>
        </div>
        <div style="flex: 1; padding: 15px; background: #f8f9fa; border-radius: 8px; margin: 0 5px; text-align: center;">
            <h5>3. Retrieve Data</h5>
            <p>Decrypt with your passkey</p>
        </div>
    </div>
    """, unsafe_allow_html=True)

# Main App Layout
def main():
    local_css()
    st.markdown('<div class="logo">🔒 SecureVault</div>', unsafe_allow_html=True)
    
    if not st.session_state.authenticated:
        menu = ["Login", "Register"]
        choice = st.sidebar.selectbox("Menu", menu)
        
        if choice == "Login":
            login_user()
        elif choice == "Register":
            register_user()
    else:
        st.sidebar.markdown(f"### 👤 {st.session_state.current_user}")
        if st.sidebar.button("Logout"):
            logout_user()
            
        menu = ["Dashboard", "Store Data", "Retrieve Data"]
        choice = st.sidebar.selectbox("Menu", menu)
        
        if choice == "Dashboard":
            home_page()
        elif choice == "Store Data":
            store_data()
        elif choice == "Retrieve Data":
            retrieve_data()

if __name__ == "__main__":
    main()