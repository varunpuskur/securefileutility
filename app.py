from flask import Flask, render_template, request, send_file, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import io
import hashlib
import zipfile

app = Flask(__name__)
app.secret_key = 'supersecretkey'
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['DATABASE'] = 'new_database.db'

# Custom Feistel Cipher for encryption & decryption
class Encryptor:
    def __init__(self):
        self.rounds = 10  # Feistel Cipher Rounds
        self.block_size = 16  # Block size for processing (in bytes)

    def derive_key(self, password):
        return hashlib.sha256(password.encode()).digest()[:16]  # Get 16-byte key

    def feistel_round(self, left, right, key):
        new_left = right
        new_right = bytes(l ^ r for l, r in zip(left, key))
        return new_left, new_right
    
    def compress_data(self, data):
        compressed_io = io.BytesIO()
        with zipfile.ZipFile(compressed_io, mode='w', compression=zipfile.ZIP_DEFLATED) as zf:
            zf.writestr('compressed_file', data)
        compressed_io.seek(0)
        return b'COMP' + compressed_io.read() 

    def is_valid_decryption(self, decrypted_data):
        if not decrypted_data or len(decrypted_data) < 10:
            return False 

        if decrypted_data[:4] == b'COMP':  
            return True 

        valid_bytes = sum(1 for byte in decrypted_data if 32 <= byte <= 126 or byte in (9, 10, 13))
        validity_percentage = valid_bytes / len(decrypted_data)

        return validity_percentage > 0.75  


    # Encrypt using Feistel Cipher
    def encrypt(self, file, password):
        key = self.derive_key(password)
        plaintext = file.read()
        compressed_data = self.compress_data(plaintext)  

        encrypted_data = bytearray()
        for i in range(0, len(compressed_data), self.block_size): 
            block = bytearray(compressed_data[i:i + self.block_size])
            if len(block) < self.block_size:
                block.extend([0] * (self.block_size - len(block))) 

            left, right = block[:8], block[8:]  

            for _ in range(self.rounds):
                left, right = self.feistel_round(left, right, key)

            encrypted_data.extend(left + right)

        return bytes(encrypted_data)

    def decompress_data(self, data):
        if data[:4] != b'COMP': 
            return data 
        
        decompressed_io = io.BytesIO(data[4:])  
        with zipfile.ZipFile(decompressed_io, mode='r') as zf:
            return zf.read('compressed_file')

        
    def decrypt(self, file, password):
        key = self.derive_key(password)
        encrypted_data = file.read()
        decrypted_data = bytearray()

        for i in range(0, len(encrypted_data), self.block_size):
            block = bytearray(encrypted_data[i:i + self.block_size])
            left, right = block[:8], block[8:]

            for _ in range(self.rounds):
                right, left = self.feistel_round(right, left, key)  # Reverse Feistel

            decrypted_data.extend(left + right)

        if not self.is_valid_decryption(decrypted_data):
            flash("Wrong Password! Please try again.", "error")
            return None, None 

        try:
            decompressed_data = self.decompress_data(bytes(decrypted_data))
        except zipfile.BadZipFile:
            flash("Decryption successful, but file may not be valid (no compression detected)", "error")
            return None, None  

        original_filename = file.filename.replace('.enc', '') if file.filename.endswith('.enc') else file.filename

        return decompressed_data, original_filename 

encryptor = Encryptor()

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
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
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
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
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
        file = request.files.get('file')
        password = request.form['password']
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('encrypt'))

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
            flash(f'Encryption failed: {str(e)}', 'error')
            return redirect(url_for('encrypt'))

    return render_template('encrypt.html')

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    if 'user_id' not in session:
        flash('You must be logged in to decrypt files.', 'error')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        file = request.files.get('file')
        password = request.form['password']
        if not file or file.filename == '':
            flash('No file selected.', 'error')
            return redirect(url_for('decrypt'))

        with sqlite3.connect(app.config['DATABASE']) as conn:
            c = conn.cursor()
            c.execute("SELECT id, user_id FROM files WHERE filename=?", (file.filename,))
            file_record = c.fetchone()
            
            if not file_record:
                flash("File not found in the database.", 'error')
                return redirect(url_for('decrypt'))

            file_id, file_owner_id = file_record

            c.execute("""
                SELECT 1 FROM permissions WHERE file_id=? AND user_id=?
                UNION
                SELECT 1 FROM files WHERE id=? AND user_id=?
            """, (file_id, session['user_id'], file_id, session['user_id']))
            permission_check = c.fetchone()

            if not permission_check:
                flash("You do not have permission to decrypt this file.", 'error')
                return redirect(url_for('decrypt'))

        try:
            decrypted_data, original_filename = encryptor.decrypt(file, password)

            if decrypted_data is None:
                return redirect(url_for('decrypt')) 
            
            if original_filename.endswith('.enc'):
                original_filename = original_filename[:-4]  

            return send_file(
                io.BytesIO(decrypted_data),
                mimetype='application/octet-stream',
                as_attachment=True,
                download_name=original_filename
            )

        except Exception as e:
            flash(f'Decryption failed: {str(e)}', 'error')
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




      