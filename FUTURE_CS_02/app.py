from flask import Flask, request, send_file, render_template, redirect, url_for
from werkzeug.utils import secure_filename
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
from base64 import b64decode
from dotenv import load_dotenv
import hashlib
import os
import base64
from flask import send_from_directory
from datetime import datetime


# Load .env and AES Key
load_dotenv()
key_str = os.getenv("AES_KEY")
if not key_str:
    raise ValueError("AES_KEY not found in .env")

KEY = base64.b64decode(key_str)

app = Flask("WhiteAbyss")
UPLOAD_FOLDER = "whiteabyss_uploads"
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

#Hash Calculator
def compute_sha256(data):
    sha256 = hashlib.sha256()
    sha256.update(data)
    return sha256.hexdigest()


def pad(data):
    pad_len = AES.block_size - len(data) % AES.block_size
    return data + bytes([pad_len] * pad_len)

def unpad(data):
    pad_len = data[-1]
    return data[:-pad_len]

# Encrypt the uploaded file and return encrypted bytes
def encrypt_file(file_data):
    iv = get_random_bytes(16)
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    encrypted = cipher.encrypt(pad(file_data))
    return iv + encrypted

# Decrypt the encrypted file bytes and return decrypted bytes
def decrypt_file(encrypted_data):
    iv = encrypted_data[:16]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(encrypted_data[16:])
    return unpad(decrypted)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return "No file part", 400

    file = request.files['file']
    if file.filename == '':
        return "No selected file", 400

    filename = secure_filename(file.filename)
    file_data = file.read()

    #compute and save hash
    file_hash = compute_sha256(file_data)
    hash_path = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".hash")
    with open(hash_path, "w") as h:
        h.write(file_hash)

        #encrypt and save data
    encrypted_data = encrypt_file(file_data)
    encrypted_path = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".enc")
    with open(encrypted_path, "wb") as f:
        f.write(encrypted_data)

    return f"WhiteAbyss: File '{filename}' securely uploaded and encrypted successfully."

@app.route('/download', methods=['GET'])
def download_by_name():
    filename = request.args.get("filename")
    return redirect(url_for('download_file', filename=filename))

@app.route('/download/<filename>')
def download_file(filename):
    filepath = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".enc")
    if not os.path.exists(filepath):
        return "File not found", 404

    with open(filepath, "rb") as f:
        encrypted_data = f.read()
    decrypted_data = decrypt_file(encrypted_data)

    current_hash = compute_sha256(decrypted_data)
    hash_path = os.path.join(app.config["UPLOAD_FOLDER"], filename + ".hash")
    if not os.path.exists(hash_path):
        return "Integrity hash missing! File may be tampered.", 500

    with open(hash_path, "r") as h:
        original_hash = h.read().strip()

    if current_hash != original_hash:
        return "File integrity verification failed! Hash mismatch", 500

    decrypted_path = os.path.join(app.config["UPLOAD_FOLDER"], filename)
    with open(decrypted_path, "wb") as f:
        f.write(decrypted_data)
    return send_file(decrypted_path, as_attachment=True)

if __name__ == '__main__':
    app.run(debug=True)
