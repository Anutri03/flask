import os
from flask import Flask, render_template, request, jsonify, url_for, session, redirect, flash
from werkzeug.utils import secure_filename
from flask_wtf.csrf import CSRFProtect
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
import sqlite3
from datetime import datetime

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Initialize Flask extensions
csrf = CSRFProtect(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'home'

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, fullname, email):
        self.id = id
        self.fullname = fullname
        self.email = email

    @staticmethod
    def get(user_id):
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute('SELECT * FROM users WHERE id = ?', (user_id,))
        user = c.fetchone()
        conn.close()
        if not user:
            return None
        return User(id=user[0], fullname=user[1], email=user[2])

@login_manager.user_loader
def load_user(user_id):
    return User.get(user_id)

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            fullname TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

# Initialize database on app startup
with app.app_context():
    init_db()

ALLOWED_EXTENSIONS = {
    'dcm', 'nii', 'jpg', 'jpeg', 'png', 'tiff', 'bmp', 'nrrd', 'gz', 'pdf'
}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def home():
    return render_template('login.html')

@app.route('/register')
def register():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register_post():
    fullname = request.form.get('fullname')
    email = request.form.get('email')
    password = request.form.get('password')
    confirm_password = request.form.get('confirm-password')
    terms = request.form.get('terms')

    if not all([fullname, email, password, confirm_password]):
        flash('All fields are required', 'error')
        return redirect(url_for('register'))

    if password != confirm_password:
        flash('Passwords do not match', 'error')
        return redirect(url_for('register'))

    if not terms:
        flash('Please accept the Terms & Conditions', 'error')
        return redirect(url_for('register'))

    try:
        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        
        # Check if email already exists
        c.execute('SELECT email FROM users WHERE email = ?', (email,))
        if c.fetchone():
            flash('Email already registered', 'error')
            return redirect(url_for('register'))

        # Insert new user
        hashed_password = generate_password_hash(password)
        c.execute('INSERT INTO users (fullname, email, password) VALUES (?, ?, ?)',
                 (fullname, email, hashed_password))
        conn.commit()
        conn.close()

        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('home'))

    except Exception as e:
        flash('Registration failed. Please try again.', 'error')
        return redirect(url_for('register'))

@app.route('/login', methods=['POST'])
def login():
    email = request.form.get('email')
    password = request.form.get('password')
    remember = True if request.form.get('remember') else False

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('SELECT * FROM users WHERE email = ?', (email,))
    user_data = c.fetchone()
    conn.close()

    if user_data and check_password_hash(user_data[3], password):
        user = User(id=user_data[0], fullname=user_data[1], email=user_data[2])
        login_user(user, remember=remember)
        return redirect(url_for('landingpagemain'))
    
    flash('Invalid email or password', 'error')
    return redirect(url_for('home'))

@app.route('/landingpagemain')
@login_required
def landingpagemain():
    return render_template('landingpagemain.html')

@app.route('/technology')
@login_required
def technology():
    return render_template('technology.html')

@app.route('/about')
@login_required
def about():
    return render_template('about.html')

@app.route('/research')
@login_required
def research():
    return render_template('research.html')

@app.route('/predict')
@login_required
def predict():
    return render_template('predict.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('home'))

if __name__ == '__main__':
    app.run(debug=True) 