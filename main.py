import os
import json
import hashlib
import streamlit as st
from cryptography.fernet import Fernet
from datetime import datetime, timedelta

# Generate or load encryption key
def get_fernet_key():
    if 'fernet_key' not in st.session_state:
        # In a real application, this should be stored securely
        st.session_state.fernet_key = Fernet.generate_key()
    return st.session_state.fernet_key

cipher = Fernet(get_fernet_key())

# Initialize session state variables
if 'stored_data' not in st.session_state:
    st.session_state.stored_data = {}
if 'failed_attempts' not in st.session_state:
    st.session_state.failed_attempts = 0
if 'lockout_time' not in st.session_state:
    st.session_state.lockout_time = None

# Function to hash passkey with salt
def hash_passkey(passkey, salt=None):
    if salt is None:
        salt = os.urandom(16).hex()  # Generate a random salt
    # Using PBKDF2 for better security than plain SHA-256
    hashed = hashlib.pbkdf2_hmac(
        'sha256',
        passkey.encode('utf-8'),
        salt.encode('utf-8'),
        100000  # Number of iterations
    )
    return f"{salt}${hashed.hex()}"

# Function to verify passkey
def verify_passkey(passkey, stored_hash):
    salt, _ = stored_hash.split('$')
    new_hash = hash_passkey(passkey, salt)
    return new_hash == stored_hash

# Function to encrypt data
def encrypt_data(text, passkey):
    return cipher.encrypt(text.encode()).decode()

# Function to decrypt data
def decrypt_data(encrypted_text, passkey):
    try:
        return cipher.decrypt(encrypted_text.encode()).decode()
    except:
        return None

# Check if user is locked out
def is_locked_out():
    if st.session_state.lockout_time:
        remaining_time = (st.session_state.lockout_time - datetime.now()).total_seconds()
        if remaining_time > 0:
            return True, remaining_time
        else:
            st.session_state.lockout_time = None
            st.session_state.failed_attempts = 0
    return False, 0

# Save data to JSON file
def save_data():
    with open('secure_data.json', 'w') as f:
        json.dump(st.session_state.stored_data, f)

# Load data from JSON file
def load_data():
    try:
        with open('secure_data.json', 'r') as f:
            st.session_state.stored_data = json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        st.session_state.stored_data = {}

# Load data at startup
load_data()

# Streamlit UI
st.title("🔒 Secure Data Encryption System")

# Navigation
menu = ["Home", "Store Data", "Retrieve Data", "Login"]
choice = st.sidebar.selectbox("Navigation", menu)

if choice == "Home":
    st.subheader("🏠 Welcome to the Secure Data System")
    st.write("Use this app to **securely store and retrieve data** using unique passkeys.")
    st.write("### Features:")
    st.write("- 🔐 AES-128 encryption using Fernet")
    st.write("- 🧂 Salted PBKDF2 password hashing")
    st.write("- ⏳ Temporary lockout after 3 failed attempts")
    st.write("- 📦 Data persistence using JSON storage")

elif choice == "Store Data":
    st.subheader("📂 Store Data Securely")
    user_data = st.text_area("Enter Data:")
    passkey = st.text_input("Enter Passkey:", type="password")
    confirm_passkey = st.text_input("Confirm Passkey:", type="password")
    data_name = st.text_input("Give this data a name (optional):")

    if st.button("Encrypt & Save"):
        if not user_data or not passkey:
            st.error("⚠️ Data and passkey are required!")
        elif passkey != confirm_passkey:
            st.error("⚠️ Passkeys don't match!")
        else:
            # Generate a unique ID if name not provided
            if not data_name:
                data_name = f"data_{len(st.session_state.stored_data) + 1}"
            
            # Hash the passkey
            hashed_passkey = hash_passkey(passkey)
            
            # Encrypt the data
            encrypted_text = encrypt_data(user_data, passkey)
            
            # Store the data
            st.session_state.stored_data[data_name] = {
                "encrypted_text": encrypted_text,
                "passkey": hashed_passkey,
                "timestamp": datetime.now().isoformat()
            }
            
            # Save to file
            save_data()
            
            st.success("✅ Data stored securely!")
            st.code(f"Data reference: {data_name}")

elif choice == "Retrieve Data":
    st.subheader("🔍 Retrieve Your Data")
    
    # Check if locked out
    locked, remaining = is_locked_out()
    if locked:
        st.error(f"🔒 Account locked! Please try again in {int(remaining)} seconds.")
        st.warning("Too many failed attempts. Please wait or login to reset.")
    else:
        data_name = st.selectbox(
            "Select data to retrieve:",
            options=list(st.session_state.stored_data.keys()) + ["Enter manually..."],
            index=0
        )
        
        if data_name == "Enter manually...":
            data_name = st.text_input("Enter data reference name:")
        
        passkey = st.text_input("Enter Passkey:", type="password")
        
        if st.button("Decrypt"):
            if not data_name or not passkey:
                st.error("⚠️ Both fields are required!")
            elif data_name not in st.session_state.stored_data:
                st.error("❌ Data reference not found!")
            else:
                data_entry = st.session_state.stored_data[data_name]
                encrypted_text = data_entry["encrypted_text"]
                stored_hash = data_entry["passkey"]
                
                # Verify passkey
                if verify_passkey(passkey, stored_hash):
                    decrypted_text = decrypt_data(encrypted_text, passkey)
                    if decrypted_text:
                        st.session_state.failed_attempts = 0
                        st.success("✅ Decryption successful!")
                        st.text_area("Decrypted Data:", value=decrypted_text, height=200)
                        st.write(f"Stored on: {data_entry['timestamp']}")
                    else:
                        st.error("❌ Decryption failed!")
                else:
                    st.session_state.failed_attempts += 1
                    remaining_attempts = 3 - st.session_state.failed_attempts
                    
                    if remaining_attempts > 0:
                        st.error(f"❌ Incorrect passkey! Attempts remaining: {remaining_attempts}")
                    else:
                        st.session_state.lockout_time = datetime.now() + timedelta(minutes=5)
                        st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
                        st.experimental_rerun()

elif choice == "Login":
    st.subheader("🔑 Reauthorization Required")
    
    # Check if locked out
    locked, remaining = is_locked_out()
    if locked:
        st.error(f"🔒 Account locked! Please try again in {int(remaining)} seconds.")
    else:
        login_pass = st.text_input("Enter Master Password:", type="password")
        
        if st.button("Login"):
            # In a real app, use proper password hashing and storage
            master_hash = hash_passkey("admin123")  # Default password for demo
            
            if verify_passkey(login_pass, master_hash):
                st.session_state.failed_attempts = 0
                st.session_state.lockout_time = None
                st.success("✅ Reauthorized successfully! Redirecting to Home...")
                st.experimental_rerun()
            else:
                st.session_state.failed_attempts += 1
                remaining_attempts = 3 - st.session_state.failed_attempts
                
                if remaining_attempts > 0:
                    st.error(f"❌ Incorrect password! Attempts remaining: {remaining_attempts}")
                else:
                    st.session_state.lockout_time = datetime.now() + timedelta(minutes=5)
                    st.error("🔒 Too many failed attempts! Account locked for 5 minutes.")
                    st.experimental_rerun()

# Display debug info in sidebar (optional)
if st.sidebar.checkbox("Show debug info"):
    st.sidebar.write("### Debug Information")
    st.sidebar.write(f"Failed attempts: {st.session_state.failed_attempts}")
    st.sidebar.write(f"Lockout time: {st.session_state.lockout_time}")
    st.sidebar.write("Stored data keys:", list(st.session_state.stored_data.keys()))