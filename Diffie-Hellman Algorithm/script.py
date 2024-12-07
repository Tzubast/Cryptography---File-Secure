import os
from flask import Flask, request, render_template, redirect, flash
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import secrets

app = Flask(__name__)
app.secret_key = 'supersecretkey'
UPLOAD_FOLDER = 'uploads'
ENCRYPTED_FOLDER = 'encrypted'
DECRYPTED_FOLDER = 'decrypted'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(ENCRYPTED_FOLDER, exist_ok=True)
os.makedirs(DECRYPTED_FOLDER, exist_ok=True)

# Diffie-Hellman Parameters
p = 23  # Example prime (use larger for real applications)
g = 5   # Example generator

# Generate DH keys
def generate_keys():
    private_key = secrets.randbelow(p)
    public_key = pow(g, private_key, p)
    return private_key, public_key

# Generate shared key
def generate_shared_key(private_key, other_public_key):
    shared_key = pow(other_public_key, private_key, p)
    return shared_key.to_bytes(16, 'big')

# Encrypt file using AES
def encrypt_file(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        plaintext = f.read()
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(plaintext, AES.block_size))
    with open(output_path, 'wb') as f:
        f.write(cipher.iv + ciphertext)

# Decrypt file using AES
def decrypt_file(file_path, output_path, key):
    with open(file_path, 'rb') as f:
        data = f.read()
    iv = data[:16]
    ciphertext = data[16:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = unpad(cipher.decrypt(ciphertext), AES.block_size)
    with open(output_path, 'wb') as f:
        f.write(plaintext)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'file' not in request.files:
        flash('No file part')
        return redirect('/')
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect('/')
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Generate DH keys and shared key
    private_key, public_key = generate_keys()
    _, other_public_key = generate_keys()  # Simulate other party
    shared_key = generate_shared_key(private_key, other_public_key)

    encrypted_path = os.path.join(ENCRYPTED_FOLDER, file.filename + '.enc')
    encrypt_file(file_path, encrypted_path, shared_key)
    flash(f'File encrypted and saved to {encrypted_path}')
    return redirect('/')

@app.route('/decrypt', methods=['POST'])
def decrypt():
    if 'file' not in request.files:
        flash('No file part')
        return redirect('/')
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect('/')
    file_path = os.path.join(UPLOAD_FOLDER, file.filename)
    file.save(file_path)

    # Generate DH keys and shared key (same process)
    private_key, public_key = generate_keys()
    _, other_public_key = generate_keys()
    shared_key = generate_shared_key(private_key, other_public_key)

    decrypted_path = os.path.join(DECRYPTED_FOLDER, file.filename + '.dec')
    decrypt_file(file_path, decrypted_path, shared_key)
    flash(f'File decrypted and saved to {decrypted_path}')
    return redirect('/')

if __name__ == '__main__':
    app.run(debug=True)
