from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import io
import zipfile

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['DATABASE'] = 'new_database.db'

# Encryptor class to handle encryption and decryption
class Encryptor:
    def __init__(self):
        self.salt_size = 16
        self.nonce_size = 16
        self.tag_size = 16

    def derive_key(self, password, salt):
        return PBKDF2(password, salt, dkLen=32, count=100000)

    def encrypt(self, file, password):
        salt = get_random_bytes(self.salt_size)
        key = self.derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_GCM)
        plaintext = self.compress_file(file)
        ciphertext, tag = cipher.encrypt_and_digest(plaintext)
        return salt + cipher.nonce + tag + ciphertext
    
    def decrypt(self, file, password):
        data = file.read()
        salt = data[:self.salt_size]
        nonce = data[self.salt_size:self.salt_size + self.nonce_size]
        tag = data[self.salt_size + self.nonce_size:self.salt_size + self.nonce_size + self.tag_size]
        ciphertext = data[self.salt_size + self.nonce_size + self.tag_size:]
        key = self.derive_key(password.encode(), salt)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        try:
            plaintext = cipher.decrypt_and_verify(ciphertext, tag)
            plaintext = self.decompress_file(plaintext)
        except (ValueError, KeyError):
            raise ValueError("Incorrect password or corrupted file")
        original_filename = os.path.splitext(file.filename)[0]
        return plaintext, original_filename

    def compress_file(self, file):
        compressed_data = io.BytesIO()
        with zipfile.ZipFile(compressed_data, mode='w', compression=zipfile.ZIP_DEFLATED) as zip_file:
            zip_file.writestr(file.filename, file.read())
        compressed_data.seek(0)
        return compressed_data.read()

    def decompress_file(self, data):
        decompressed_data = io.BytesIO(data)
        with zipfile.ZipFile(decompressed_data, mode='r') as zip_file:
            for name in zip_file.namelist():
                return zip_file.read(name)

encryptor = Encryptor()

# Initialize the database
def init_db():
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY, 
                username TEXT UNIQUE, 
                password TEXT
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS files (
                id INTEGER PRIMARY KEY, 
                filename TEXT, 
                user_id INTEGER, 
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        ''')
        c.execute('''
            CREATE TABLE IF NOT EXISTS permissions (
                file_id INTEGER, 
                user_id INTEGER, 
                FOREIGN KEY(file_id) REFERENCES files(id), 
                FOREIGN KEY(user_id) REFERENCES users(id),
                PRIMARY KEY (file_id, user_id)
            )
        ''')

@app.route('/')
def login_redirect():
    return redirect(url_for('login'))

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='sha256')
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            try:
                c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
                conn.commit()
                flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                flash('Username already exists.')
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute("SELECT id, password FROM users WHERE username=?", (username,))
            user = c.fetchone()
        if user and check_password_hash(user[1], password):
            session['user_id'] = user[0]
            flash('Login successful!')
            return redirect(url_for('home'))
        else:
            error = 'Wrong username or password. Please try again.'
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.')
    return redirect(url_for('login'))

@app.route('/home')
def home():
    if 'user_id' not in session:
        flash('You must be logged in to view this page.')
        return redirect(url_for('login'))
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    if 'user_id' not in session:
        flash('You must be logged in to encrypt files.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            return 'No file part', 400
        file = request.files['file']
        if file.filename == '':
            return 'No selected file', 400
        if file:
            password = request.form['password']
            try:
                encrypted_data = encryptor.encrypt(file, password)
                encrypted_filename = file.filename + '.enc'
                with sqlite3.connect(app.config['DATABASE']) as conn:
                    c = conn.cursor()
                    c.execute("INSERT INTO files (filename, user_id) VALUES (?, ?)", (encrypted_filename, session['user_id']))
                    file_id = c.lastrowid
                    c.execute("INSERT INTO permissions (file_id, user_id) VALUES (?, ?)", (file_id, session['user_id']))
                    conn.commit()
                return send_file(
                    io.BytesIO(encrypted_data),
                    mimetype='application/octet-stream',
                    as_attachment=True,
                    download_name=encrypted_filename
                )
            except Exception as e:
                return f'Encryption failed: {str(e)}', 500
    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'user_id' not in session:
        flash('You must be logged in to decrypt files.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        if 'file' not in request.files:
            flash('No file part', 'error')
            return redirect(url_for('decrypt'))
        file = request.files['file']
        if file.filename == '':
            flash('No selected file', 'error')
            return redirect(url_for('decrypt'))
        if file:
            password = request.form['password']
            try:
                with sqlite3.connect(app.config['DATABASE']) as conn:
                    c = conn.cursor()
                    c.execute("SELECT id, user_id FROM files WHERE filename=?", (file.filename,))
                    file_record = c.fetchone()
                    has_permission = False
                    if file_record:
                        file_id, file_owner_id = file_record
                        c.execute("""
                            SELECT 1 FROM permissions 
                            WHERE file_id=? AND user_id=?
                            UNION
                            SELECT 1 FROM files
                            WHERE id=? AND user_id=?
                        """, (file_id, session['user_id'], file_id, session['user_id']))
                        permission_check = c.fetchone()
                        has_permission = permission_check is not None
                if has_permission:
                    try:
                        decrypted_data, original_filename = encryptor.decrypt(file, password)
                        decrypted_filename = f"{os.path.splitext(original_filename)[0]}_decrypted{os.path.splitext(original_filename)[1]}"
                        return send_file(
                            io.BytesIO(decrypted_data),
                            mimetype='application/octet-stream',
                            as_attachment=True,
                            download_name=decrypted_filename
                        )
                    except ValueError as e:
                        flash(f'Decryption failed: {str(e)}', 'error')
                        return redirect(url_for('decrypt'))
                else:
                    flash('You do not have permission to decrypt this file.', 'error')
                    return redirect(url_for('decrypt'))
            except Exception as e:
                flash(f'An error occurred: {str(e)}', 'error')
                return redirect(url_for('decrypt'))
    return render_template('decrypt.html')

@app.route('/manage_access', methods=['GET', 'POST'])
def manage_access():
    if 'user_id' not in session:
        flash('You must be logged in to manage access.')
        return redirect(url_for('login'))
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute("""
            SELECT f.id, f.filename, GROUP_CONCAT(u.username) as granted_users
            FROM files f
            LEFT JOIN permissions p ON f.id = p.file_id
            LEFT JOIN users u ON p.user_id = u.id
            WHERE f.user_id = ?
            GROUP BY f.id
        """, (session['user_id'],))
        user_files = c.fetchall()
    
    return render_template('manage_access.html', user_files=user_files)

@app.route('/grant_access', methods=['POST'])
def grant_access():
    if 'user_id' not in session:
        flash('You must be logged in to grant access.')
        return redirect(url_for('login'))
    
    file_id = request.form['file_id']
    username = request.form['username']
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute("SELECT user_id FROM files WHERE id=?", (file_id,))
        file_owner = c.fetchone()
        if file_owner and file_owner[0] == session['user_id']:
            c.execute("SELECT id FROM users WHERE username=?", (username,))
            user = c.fetchone()
            if user:
                user_id = user[0]
                try:
                    c.execute("INSERT INTO permissions (file_id, user_id) VALUES (?, ?)", (file_id, user_id))
                    conn.commit()
                    flash(f'Access granted to {username}.')
                except sqlite3.IntegrityError:
                    flash(f'{username} already has access.')
            else:
                flash(f'User {username} not found.')
        else:
            flash('You do not have permission to grant access to this file.')
    
    return redirect(url_for('manage_access'))

@app.route('/revoke_access', methods=['POST'])
def revoke_access():
    if 'user_id' not in session:
        flash('You must be logged in to revoke access.')
        return redirect(url_for('login'))
    
    file_id = request.form['file_id']
    username = request.form['username']
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute("SELECT id FROM users WHERE username=?", (username,))
        user = c.fetchone()
        if user:
            user_id = user[0]
            c.execute("DELETE FROM permissions WHERE file_id=? AND user_id=?", (file_id, user_id))
            conn.commit()
            flash(f'Access revoked from {username}.')
        else:
            flash(f'User {username} not found.')
    
    return redirect(url_for('manage_access'))

@app.route('/remove_file', methods=['POST'])
def remove_file():
    if 'user_id' not in session:
        flash('You must be logged in to remove files.')
        return redirect(url_for('login'))
    
    file_id = request.form['file_id']
    
    with sqlite3.connect(app.config['DATABASE']) as conn:
        c = conn.cursor()
        c.execute("SELECT user_id FROM files WHERE id=?", (file_id,))
        file_owner = c.fetchone()
        if file_owner and file_owner[0] == session['user_id']:
            c.execute("DELETE FROM permissions WHERE file_id=?", (file_id,))
            c.execute("DELETE FROM files WHERE id=?", (file_id,))
            conn.commit()
            flash('File removed successfully.')
        else:
            flash('You do not have permission to remove this file.')
    
    return redirect(url_for('manage_access'))

if __name__ == '__main__':
    init_db()
    app.run(debug=True)
