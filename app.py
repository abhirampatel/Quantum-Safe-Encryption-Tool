import os
import boto3
from flask import Flask, render_template, request, redirect, url_for, session, flash, send_file
from werkzeug.utils import secure_filename
import sqlite3
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.padding import OAEP, MGF1
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from io import BytesIO
from cryptography.hazmat.primitives import serialization
from datetime import datetime
import hashlib
from braket.circuits import Circuit
from braket.devices import LocalSimulator

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.urandom(24)  # Secret key for session management
app.config['UPLOAD_FOLDER'] = 'uploads'
# Allowed extensions for generic files (adjust as needed)
app.config['ALLOWED_EXTENSIONS'] = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'mp3', 'wav', 'flac'}
app.config['PRIVATE_KEY_FOLDER'] = 'private_keys'

# S3 Configuration (keep these unchanged)
S3_BUCKET_NAME = 'quantumsafe'
S3_ACCESS_KEY = ''
S3_SECRET_KEY = ''
S3_REGION = 'eu-north-1'

# Initialize Boto3 S3 client
s3_client = boto3.client(
    's3',
    aws_access_key_id=S3_ACCESS_KEY,
    aws_secret_access_key=S3_SECRET_KEY,
    region_name=S3_REGION
)

# Function to check allowed file extensions
def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in app.config['ALLOWED_EXTENSIONS']

# Function to upload a file to S3
def upload_file_to_s3(file, filename):
    try:
        s3_client.upload_fileobj(file, S3_BUCKET_NAME, filename)
        file_url = f"https://{S3_BUCKET_NAME}.s3.{S3_REGION}.amazonaws.com/{filename}"
        return file_url
    except Exception as e:
        print(f"Error uploading file to S3: {e}")
        return None

# MDI-QKD simulation (now file-specific)
def mdi_qkd_simulation(file_name):
    device = LocalSimulator()

    # Alice's Circuit
    alice_circuit = Circuit()
    alice_circuit.h(0)
    alice_circuit.rx(0, 1.57)

    # Bob's Circuit
    bob_circuit = Circuit()
    bob_circuit.h(1)
    bob_circuit.rx(1, 1.57)

    # Charlie's Measurement Circuit (Entanglement swapping)
    charlie_circuit = Circuit()
    charlie_circuit.cnot(0, 1)
    charlie_circuit.h(0)
    charlie_circuit.measure(0)
    charlie_circuit.measure(1)

    # Execute circuits on a local simulator
    result_alice = device.run(alice_circuit, shots=1000).result()
    result_bob = device.run(bob_circuit, shots=1000).result()
    result_charlie = device.run(charlie_circuit, shots=1000).result()

    # Extract keys based on measurement outcomes (simplified)
    key_alice = "".join([str(bit) for bit in result_alice.measurement_counts.keys()])
    key_bob = "".join([str(bit) for bit in result_bob.measurement_counts.keys()])
    key_charlie = "".join([str(bit) for bit in result_charlie.measurement_counts.keys()])
    shared_key = key_alice[:len(key_charlie)]

    # Use file-specific data (the filename) to generate a unique key
    file_key = hashlib.sha256(file_name.encode('utf-8')).hexdigest()
    return file_key

# Hybrid encryption (AES for file data and RSA for AES key)
def pqc_encryption(shared_key, plaintext):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    aes_key = os.urandom(32)  # AES-256 key
    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(plaintext) + padder.finalize()
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    encrypted_aes_key = public_key.encrypt(
        aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return (encrypted_aes_key, iv, ciphertext), private_key

# Hybrid decryption
def pqc_decryption(private_key, encrypted_data):
    encrypted_aes_key, iv, ciphertext = encrypted_data
    aes_key = private_key.decrypt(
        encrypted_aes_key,
        OAEP(
            mgf=MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()
    padded_data = decryptor.update(ciphertext) + decryptor.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    plaintext = unpadder.update(padded_data) + unpadder.finalize()
    return plaintext

# Database connection and initialization
def get_db_connection():
    conn = sqlite3.connect('fileapp.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    conn.execute('DROP TABLE IF EXISTS files')
    conn.execute('''CREATE TABLE IF NOT EXISTS users (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        username TEXT NOT NULL,
                        password TEXT NOT NULL)''')
    conn.execute('''CREATE TABLE IF NOT EXISTS files (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        filename TEXT NOT NULL,
                        file_size INTEGER NOT NULL,
                        timestamp TEXT NOT NULL,
                        encrypted_data BLOB NOT NULL,
                        private_key_filename TEXT NOT NULL,
                        user_id INTEGER,
                        file_url TEXT,
                        FOREIGN KEY (user_id) REFERENCES users (id))''')
    conn.commit()
    conn.close()

# Routes for landing, registration, login, file upload and download

@app.route('/')
def landing_page():
    return render_template('landing.html')

@app.route('/index')
def index():
    if 'user_id' not in session:
        return redirect(url_for('landing_page'))
    conn = get_db_connection()
    files = conn.execute('SELECT * FROM files WHERE user_id = ?', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('index.html', files=files)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        conn.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, password))
        conn.commit()
        conn.close()
        flash('You have successfully registered!', 'success')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        conn = get_db_connection()
        user = conn.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password)).fetchone()
        conn.close()
        if user:
            session['user_id'] = user['id']
            flash('You have successfully logged in!', 'success')
            return redirect(url_for('index'))
        else:
            flash('Invalid credentials. Please try again.', 'danger')
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have logged out successfully.', 'success')
    return redirect(url_for('landing_page'))

# File upload route
@app.route('/upload', methods=['GET', 'POST'])
def upload_file():
    if 'user_id' not in session:
        flash('You must be logged in to upload files!', 'danger')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file_content = file.read()
            file_size = len(file_content)
            
            # Upload the original file to S3 (reset file pointer using BytesIO)
            original_file_io = BytesIO(file_content)
            file_url = upload_file_to_s3(original_file_io, filename)
            
            if file_url:
                # Generate a file-specific shared key
                shared_key = mdi_qkd_simulation(filename)
                encrypted_data, private_key = pqc_encryption(shared_key, file_content)
                
                timestamp = datetime.now().strftime('%Y%m%d%H%M%S')
                private_key_filename = f"file_{filename}_{timestamp}_private_key.pem"
                private_key_bytes = private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.TraditionalOpenSSL,
                    encryption_algorithm=serialization.NoEncryption()
                )
                private_key_file = BytesIO(private_key_bytes)
                
                # Upload the private key to S3
                upload_file_to_s3(private_key_file, private_key_filename)
                
                # Prepare encrypted file data (concatenate encrypted AES key, IV and ciphertext)
                encrypted_aes_key, iv, ciphertext = encrypted_data
                encrypted_data_binary = encrypted_aes_key + iv + ciphertext
                encrypted_filename = f"encrypted_{filename}"
                encrypted_file_io = BytesIO(encrypted_data_binary)
                encrypted_file_url = upload_file_to_s3(encrypted_file_io, encrypted_filename)
                
                # Save file metadata and S3 links in the database
                conn = get_db_connection()
                conn.execute('INSERT INTO files (filename, file_size, timestamp, encrypted_data, private_key_filename, user_id, file_url) VALUES (?, ?, ?, ?, ?, ?, ?)', 
                             (filename, file_size, timestamp, encrypted_file_url, private_key_filename, session['user_id'], file_url))
                conn.commit()
                conn.close()
                
                flash('File uploaded and encrypted successfully!', 'success')
                return redirect(url_for('index'))
            else:
                flash('Error uploading original file to S3', 'danger')
                return redirect(request.url)
    return render_template('upload.html')

# File download (decryption) route
@app.route('/download/<int:file_id>')
def download_file(file_id):
    conn = get_db_connection()
    file_record = conn.execute('SELECT * FROM files WHERE id = ?', (file_id,)).fetchone()
    conn.close()
    
    if file_record:
        encrypted_file_url = file_record['encrypted_data']
        private_key_filename = file_record['private_key_filename']
        
        # Extract S3 key for the encrypted file
        s3_key = encrypted_file_url.split(f"https://{S3_BUCKET_NAME}.s3.{S3_REGION}.amazonaws.com/")[-1]
        encrypted_file = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=s3_key)['Body'].read()
        private_key_file = s3_client.get_object(Bucket=S3_BUCKET_NAME, Key=private_key_filename)['Body'].read()
        
        private_key = serialization.load_pem_private_key(private_key_file, password=None, backend=default_backend())
        # Decrypt the file (the first 256 bytes are the encrypted AES key, next 16 the IV)
        encrypted_data = (encrypted_file[:256], encrypted_file[256:272], encrypted_file[272:])
        decrypted_file = pqc_decryption(private_key, encrypted_data)
        
        return send_file(
            BytesIO(decrypted_file),
            as_attachment=True,
            download_name=file_record['filename'],
            mimetype='application/octet-stream'
        )
    
    flash('File not found', 'danger')
    return redirect(url_for('index'))

if __name__ == '__main__':
    init_db()  # Create database tables
    app.run(debug=True)
