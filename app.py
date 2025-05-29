from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import base64
import time

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Intentionally weak secret key

# Vulnerable Database Setup
DATABASE = 'users.db'

def init_db():
    try:
        # Ensure the database file is closed and removed if it exists
        if os.path.exists(DATABASE):
            try:
                os.remove(DATABASE)
            except:
                pass

        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        
        # Create users table
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT NOT NULL,
                     password TEXT NOT NULL,
                     is_admin BOOLEAN DEFAULT 0)''')
        
        # Create notes table
        c.execute('''CREATE TABLE IF NOT EXISTS notes
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT NOT NULL,
                     content TEXT NOT NULL)''')
        
        # Insert default admin user with weak credentials
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('admin', 'admin123', True))
        
        # Insert a regular test user
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('user', 'password123', False))
        
        conn.commit()
        conn.close()
        print("Database initialized successfully!")
    except Exception as e:
        print(f"Error initializing database: {e}")
        if os.path.exists(DATABASE):
            try:
                os.remove(DATABASE)
            except:
                pass
        raise e

def get_db():
    try:
        conn = sqlite3.connect(DATABASE)
        conn.row_factory = sqlite3.Row
        return conn
    except Exception as e:
        print(f"Error connecting to database: {e}")
        return None

def generate_session_token(username):
    # Intentionally weak session token generation
    timestamp = str(int(time.time()))
    token = base64.b64encode(f"{username}:{timestamp}".encode()).decode()
    return token

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            conn = get_db()
            if not conn:
                return render_template('login.html', error='Database connection error')
            
            c = conn.cursor()
            # Intentionally vulnerable to SQL injection
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            result = c.execute(query).fetchone()
            conn.close()

            if result:
                session['logged_in'] = True
                session['username'] = username
                session['token'] = generate_session_token(username)
                session['is_admin'] = bool(result[3])
                
                if session['is_admin']:
                    return render_template('dashboard.html', 
                                        username=username, 
                                        admin_message="Admin panel available at /admin")
                return redirect(url_for('dashboard'))
            
            return render_template('login.html', error='Invalid credentials')
            
        except Exception as e:
            # For SQL injection debugging - intentionally reveal error
            return render_template('login.html', error=f'Error: {str(e)}')
    
    return render_template('login.html')

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Get user's notes
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    notes = c.execute("SELECT content FROM notes WHERE username=?", 
                     (session['username'],)).fetchall()
    conn.close()
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         notes=[note[0] for note in notes],
                         is_admin=session.get('is_admin', False))

@app.route('/add_note', methods=['POST'])
def add_note():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    note_content = request.form.get('note', '')
    
    # Intentionally vulnerable to XSS - no input sanitization
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("INSERT INTO notes (username, content) VALUES (?, ?)",
              (session['username'], note_content))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/admin')
def admin_panel():
    # Intentionally weak admin check
    if session.get('token', '').startswith('YWRtaW4'):  # base64 of 'admin'
        conn = sqlite3.connect(DATABASE)
        c = conn.cursor()
        users = c.execute("SELECT username, password, is_admin FROM users").fetchall()
        notes = c.execute("SELECT username, content FROM notes").fetchall()
        conn.close()
        return render_template('admin.html', users=users, notes=notes)
    return "Unauthorized", 403

@app.route('/api/check_admin')
def check_admin():
    # Intentionally vulnerable endpoint that reveals admin check logic
    token = request.args.get('token', '')
    is_admin = token.startswith('YWRtaW4')
    return jsonify({'is_admin': is_admin})

if __name__ == '__main__':
    init_db()  # Initialize database when starting the app
    app.run(debug=True)  # Debug mode enabled intentionally 