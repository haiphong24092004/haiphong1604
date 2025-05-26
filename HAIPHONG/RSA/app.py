from flask import Flask, render_template, request, redirect, url_for, send_file, flash, session
from werkzeug.utils import secure_filename
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.Hash import SHA256
from Crypto.Random import get_random_bytes
from datetime import datetime
import os
import logging
import hashlib
from io import BytesIO

app = Flask(__name__)
app.secret_key = 'your-very-secure-secret-key-rsa-123'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['KEYS_FOLDER'] = 'keys'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Tạo thư mục nếu chưa tồn tại
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
os.makedirs(app.config['KEYS_FOLDER'], exist_ok=True)

def generate_rsa_keys(key_size=2048):
    """Tạo cặp khóa RSA và lưu vào thư mục keys"""
    key = RSA.generate(key_size)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    private_key_path = os.path.join(app.config['KEYS_FOLDER'], f'private_key_{timestamp}.pem')
    public_key_path = os.path.join(app.config['KEYS_FOLDER'], f'public_key_{timestamp}.pem')
    
    with open(private_key_path, 'wb') as f:
        f.write(private_key)
    
    with open(public_key_path, 'wb') as f:
        f.write(public_key)
    
    # Lưu nội dung khóa vào session
    session['private_key_content'] = private_key.decode('utf-8')
    session['public_key_content'] = public_key.decode('utf-8')
    session['private_key_path'] = private_key_path
    session['public_key_path'] = public_key_path
    
    return private_key_path, public_key_path

def calculate_sha256(file_path: str) -> str:
    """Tính toán SHA256 hash của file"""
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def encrypt_file_rsa(file_path: str, public_key_path: str) -> str:
    """Mã hóa file bằng RSA public key"""
    # Đọc public key
    with open(public_key_path, 'rb') as f:
        public_key = RSA.import_key(f.read())
    
    # Đọc file cần mã hóa
    with open(file_path, 'rb') as f:
        plain_data = f.read()
    
    # Tạo cipher RSA với OAEP padding
    cipher_rsa = PKCS1_OAEP.new(public_key)
    
    # RSA chỉ có thể mã hóa dữ liệu nhỏ, nên ta sẽ:
    # 1. Tạo một session key ngẫu nhiên cho AES
    # 2. Mã hóa dữ liệu bằng AES với session key
    # 3. Mã hóa session key bằng RSA
    session_key = get_random_bytes(16)
    
    # Mã hóa session key bằng RSA
    enc_session_key = cipher_rsa.encrypt(session_key)
    
    # Mã hóa dữ liệu bằng AES với session key
    cipher_aes = AES.new(session_key, AES.MODE_EAX)
    ciphertext, tag = cipher_aes.encrypt_and_digest(plain_data)
    
    # Lưu file mã hóa (định dạng: [enc_session_key][nonce][tag][ciphertext])
    encrypted_file_path = file_path + '.enc'
    with open(encrypted_file_path, 'wb') as f:
        [f.write(x) for x in (enc_session_key, cipher_aes.nonce, tag, ciphertext)]
    
    return encrypted_file_path

def decrypt_file_rsa(encrypted_file_path: str, private_key_path: str) -> str:
    """Giải mã file bằng RSA private key"""
    # Đọc private key
    with open(private_key_path, 'rb') as f:
        private_key = RSA.import_key(f.read())
    
    # Đọc file mã hóa
    with open(encrypted_file_path, 'rb') as f:
        enc_session_key = f.read(private_key.size_in_bytes())
        nonce = f.read(16)
        tag = f.read(16)
        ciphertext = f.read()
    
    # Giải mã session key bằng RSA
    cipher_rsa = PKCS1_OAEP.new(private_key)
    session_key = cipher_rsa.decrypt(enc_session_key)
    
    # Giải mã dữ liệu bằng AES
    cipher_aes = AES.new(session_key, AES.MODE_EAX, nonce)
    plain_data = cipher_aes.decrypt_and_verify(ciphertext, tag)
    
    # Lưu file giải mã
    decrypted_file_path = encrypted_file_path.replace('.enc', '.dec')
    with open(decrypted_file_path, 'wb') as f:
        f.write(plain_data)
    
    return decrypted_file_path

@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        if 'generate_keys' in request.form:
            # Tạo cặp khóa mới
            try:
                private_key_path, public_key_path = generate_rsa_keys()
                flash('RSA key pair generated successfully!', 'success')
            except Exception as e:
                logger.error(f'Key generation error: {str(e)}', exc_info=True)
                flash(f'Key generation failed: {str(e)}', 'error')
            
            return redirect(url_for('index'))
        
        elif 'encrypt_file' in request.form:
            # Xử lý mã hóa file
            if 'public_key_file' not in request.files:
                flash('No public key file selected', 'error')
                return redirect(request.url)
                
            public_key_file = request.files['public_key_file']
            if public_key_file.filename == '':
                flash('No public key file selected', 'error')
                return redirect(request.url)
            
            if 'plaintext_file' not in request.files:
                flash('No file selected for encryption', 'error')
                return redirect(request.url)
                
            plaintext_file = request.files['plaintext_file']
            if plaintext_file.filename == '':
                flash('No file selected for encryption', 'error')
                return redirect(request.url)
            
            try:
                # Lưu public key tạm
                public_key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_public_key.pem')
                public_key_file.save(public_key_path)
                
                # Lưu file cần mã hóa
                plaintext_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(plaintext_file.filename))
                plaintext_file.save(plaintext_path)
                
                # Tính toán hash của file gốc
                original_hash = calculate_sha256(plaintext_path)
                session['original_hash'] = original_hash
                session['original_filename'] = plaintext_file.filename
                
                # Mã hóa file
                encrypted_file_path = encrypt_file_rsa(plaintext_path, public_key_path)
                session['encrypted_file_path'] = encrypted_file_path
                
                flash('File encrypted successfully with RSA!', 'success')
            except Exception as e:
                logger.error(f'Encryption error: {str(e)}', exc_info=True)
                flash(f'Encryption failed: {str(e)}', 'error')
            
            return redirect(url_for('index'))
    
    return render_template('index.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if request.method == 'POST':
        if 'decrypt_file' in request.form:
            # Xử lý giải mã file
            if 'private_key_file' not in request.files:
                flash('No private key file selected', 'error')
                return redirect(request.url)
                
            private_key_file = request.files['private_key_file']
            if private_key_file.filename == '':
                flash('No private key file selected', 'error')
                return redirect(request.url)
            
            if 'encrypted_file' not in request.files:
                flash('No encrypted file selected', 'error')
                return redirect(request.url)
                
            encrypted_file = request.files['encrypted_file']
            if encrypted_file.filename == '':
                flash('No encrypted file selected', 'error')
                return redirect(request.url)
            
            try:
                # Lưu private key tạm
                private_key_path = os.path.join(app.config['UPLOAD_FOLDER'], 'temp_private_key.pem')
                private_key_file.save(private_key_path)
                
                # Lưu file mã hóa
                encrypted_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(encrypted_file.filename))
                encrypted_file.save(encrypted_path)
                
                # Giải mã file
                decrypted_file_path = decrypt_file_rsa(encrypted_path, private_key_path)
                session['decrypted_file_path'] = decrypted_file_path
                session['decrypted_filename'] = encrypted_file.filename.replace('.enc', '')
                
                # Tính toán hash của file giải mã
                decrypted_hash = calculate_sha256(decrypted_file_path)
                session['decrypted_hash'] = decrypted_hash
                
                # Kiểm tra tính toàn vẹn nếu có hash gốc
                if 'original_hash' in session:
                    session['integrity_check'] = (decrypted_hash == session['original_hash'])
                
                flash('File decrypted successfully with RSA!', 'success')
            except Exception as e:
                logger.error(f'Decryption error: {str(e)}', exc_info=True)
                flash(f'Decryption failed: {str(e)}', 'error')
            
            return redirect(url_for('decrypt'))
    
    return render_template('decrypt.html')

@app.route('/download_encrypted')
def download_encrypted():
    try:
        if 'encrypted_file_path' not in session:
            flash('No encrypted file available', 'error')
            return redirect(url_for('index'))
        
        file_path = session['encrypted_file_path']
        original_name = session.get('original_filename', 'file')  # ví dụ: image.png

        if not os.path.isfile(file_path):
            flash('Encrypted file no longer exists', 'error')
            return redirect(url_for('index'))

        with open(file_path, 'rb') as f:
            data = f.read()

        return send_file(
            BytesIO(data),
            as_attachment=True,
            download_name=f"{original_name}.enc",  # ✅ thêm .enc rõ ràng
            mimetype='application/octet-stream'
        )

    except Exception as e:
        flash(f'Download failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download_decrypted')
def download_decrypted():
    try:
        if 'decrypted_file_path' not in session:
            flash('No decrypted file available', 'error')
            return redirect(url_for('decrypt'))
        
        file_path = session['decrypted_file_path']
        original_name = session.get('decrypted_filename', 'decrypted_file')

        if not os.path.isfile(file_path):
            flash('Decrypted file no longer exists', 'error')
            return redirect(url_for('decrypt'))

        with open(file_path, 'rb') as f:
            data = f.read()

        return send_file(
            BytesIO(data),
            as_attachment=True,
            download_name=f'decrypted_{original_name}',
            mimetype='application/octet-stream'
        )

    except Exception as e:
        flash(f'Download failed: {str(e)}', 'error')
        return redirect(url_for('decrypt'))

@app.route('/download_public_key')
def download_public_key():
    try:
        if 'public_key_content' not in session:
            flash('No public key available', 'error')
            return redirect(url_for('index'))
        
        # Tạo file trong bộ nhớ
        file_data = BytesIO()
        file_data.write(session['public_key_content'].encode('utf-8'))
        file_data.seek(0)
        
        return send_file(
            file_data,
            as_attachment=True,
            download_name="public_key.pem",
            mimetype='application/x-pem-file'
        )
    except Exception as e:
        logger.error(f'Public key download error: {str(e)}', exc_info=True)
        flash(f'Public key download failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/download_private_key')
def download_private_key():
    try:
        if 'private_key_content' not in session:
            flash('No private key available', 'error')
            return redirect(url_for('index'))
        
        # Tạo file trong bộ nhớ
        file_data = BytesIO()
        file_data.write(session['private_key_content'].encode('utf-8'))
        file_data.seek(0)
        
        return send_file(
            file_data,
            as_attachment=True,
            download_name="private_key.pem",
            mimetype='application/x-pem-file'
        )
    except Exception as e:
        logger.error(f'Private key download error: {str(e)}', exc_info=True)
        flash(f'Private key download failed: {str(e)}', 'error')
        return redirect(url_for('index'))

@app.route('/cleanup', methods=['POST'])
def cleanup():
    try:
        # Xóa file trong thư mục uploads
        deleted_files = 0
        for filename in os.listdir(app.config['UPLOAD_FOLDER']):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            try:
                if os.path.isfile(file_path):
                    os.unlink(file_path)
                    deleted_files += 1
            except Exception as e:
                logger.error(f'Error deleting {filename}: {str(e)}')
                continue
        
        # Xóa session data
        session_keys = [
            'private_key_path', 'public_key_path', 'public_key_content', 'private_key_content',
            'encrypted_file_path', 'original_filename', 'original_hash',
            'decrypted_file_path', 'decrypted_filename', 'decrypted_hash', 'integrity_check'
        ]
        for key in session_keys:
            session.pop(key, None)
        
        flash(f'Cleanup completed! Removed {deleted_files} temporary files.', 'success')
    except Exception as e:
        logger.error(f'Cleanup error: {str(e)}', exc_info=True)
        flash(f'Cleanup failed: {str(e)}', 'error')
    
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, port=5000)