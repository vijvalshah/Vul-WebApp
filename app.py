from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import base64
import time
import re

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Intentionally weak secret key

# Vulnerable Database Setup
DATABASE = 'users.db'

# Flag definitions
FLAGS = {
    'sql_injection': 'CYSM{dhviue23djnfo32xwq}',
    'privilege_escalation': 'CYSM{asde2f4vdvaaae2e1}',
    'session_token': 'CYSM{Asdvrnidn02f35das}',
    'stored_xss': 'CYSM{dfwwwwfw9e0dw2}',
    'admin_panel': 'CYSM{w3xsspo34se2}',
    'hidden_info': 'CYSM{cr3kdkas2unkn0wn}'
}

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
        
        # Create solved_challenges table
        c.execute('''CREATE TABLE IF NOT EXISTS solved_challenges
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                     username TEXT NOT NULL,
                     challenge_name TEXT NOT NULL,
                     solved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Insert default admin user with weak credentials
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('admin', 'Z0J5jHJm!9B9s#', True))
        
        # Insert a regular test user
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('user', 'password123', False))
        
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('Unknown', 'Th3w3eknd15th3be35T', False))
        
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('cyscom', 'bifb3iub98#$dfs', False))
        
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

def mark_challenge_solved(username, challenge_name):
    try:
        conn = get_db()
        c = conn.cursor()
        # Check if already solved
        result = c.execute(
            "SELECT id FROM solved_challenges WHERE username=? AND challenge_name=?",
            (username, challenge_name)
        ).fetchone()
        
        if not result:
            c.execute(
                "INSERT INTO solved_challenges (username, challenge_name) VALUES (?, ?)",
                (username, challenge_name)
            )
            conn.commit()
            return True
    except Exception as e:
        print(f"Error marking challenge as solved: {e}")
    finally:
        conn.close()
    return False

def get_solved_challenges(username):
    try:
        conn = get_db()
        c = conn.cursor()
        solved = c.execute(
            "SELECT challenge_name FROM solved_challenges WHERE username=?",
            (username,)
        ).fetchall()
        return [row[0] for row in solved]
    except Exception as e:
        print(f"Error getting solved challenges: {e}")
        return []
    finally:
        conn.close()

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
            
            # Block OR-based SQL injections
            or_patterns = [
                r"(?i)'\s*or\s*'?1\s*=\s*'?1",  # matches ' OR '1'='1 and variations
                r"(?i)'\s*or\s*1\s*=\s*1",      # matches ' OR 1=1 and variations
                r"(?i)'\s*or\s*true",           # matches ' OR TRUE and variations
                r"(?i)'\s*or\s*[0-9]+\s*=\s*[0-9]+", # matches ' OR 2=2 and variations
            ]
            
            if any(re.search(pattern, username) or re.search(pattern, password) for pattern in or_patterns):
                return render_template('login.html', error='Nice try! OR-based injections are blocked. Try another technique!')
            
            # Intentionally vulnerable to SQL injection (but not OR-based ones)
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            result = c.execute(query).fetchone()
            conn.close()

            if result:
                session['logged_in'] = True
                session['username'] = username
                session['token'] = generate_session_token(username)
                session['is_admin'] = bool(result[3])
                
                # Check for SQL injection - award for any successful injection
                sql_patterns = [
                    r"(?i)--",                   # SQL comment
                    r"(?i)#",                    # SQL comment
                    r"(?i)/\*",                  # SQL comment block
                    r"(?i)union",                # UNION attack
                    r"(?i)'\s*;",                # SQL query stacking
                    r"(?i)'\s*$"                 # Single quote at end
                ]
                
                # Check if this is a SQL injection attempt
                is_injection = any(re.search(pattern, username) or re.search(pattern, password) for pattern in sql_patterns)
                
                if is_injection:
                    # Verify it's not a normal login
                    check_conn = get_db()
                    check_c = check_conn.cursor()
                    normal_query = "SELECT * FROM users WHERE username=? AND password=?"
                    normal_result = check_c.execute(normal_query, (username, password)).fetchone()
                    check_conn.close()
                    
                    if not normal_result and mark_challenge_solved(username, 'sql_injection'):
                        flash(f"Congratulations! You solved the SQL Injection challenge! Flag: {FLAGS['sql_injection']}")
                
                # Only award privilege escalation flag for legitimate admin login
                if session['is_admin'] and username == 'admin' and password == 'Z0J5jHJm!9B9s#':
                    if mark_challenge_solved(username, 'privilege_escalation'):
                        flash(f"Congratulations! You gained admin access with legitimate credentials! Flag: {FLAGS['privilege_escalation']}")
                
                return redirect(url_for('dashboard'))
            
            return render_template('login.html', error='Invalid credentials')
            
        except Exception as e:
            # For SQL injection debugging - intentionally reveal error
            return render_template('login.html', error=f'Error: {str(e)}')
    
    return render_template('login.html')

@app.route('/flags')
def flags():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Get solved challenges
    solved_challenges = get_solved_challenges(session['username'])
    
    return render_template('flags.html', 
                         username=session['username'],
                         solved_challenges=solved_challenges,
                         flags=FLAGS)

@app.route('/dashboard')
def dashboard():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Get user's notes
    conn = get_db()
    c = conn.cursor()
    notes = c.execute("SELECT content FROM notes WHERE username=?", 
                     (session['username'],)).fetchall()
    conn.close()
    
    # Get solved challenges
    solved_challenges = get_solved_challenges(session['username'])
    
    return render_template('dashboard.html', 
                         username=session['username'],
                         notes=[note[0] for note in notes],
                         is_admin=session.get('is_admin', False),
                         solved_challenges=solved_challenges)

@app.route('/add_note', methods=['POST'])
def add_note():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    note_content = request.form.get('note', '')
    
    # Check for XSS attempt
    xss_patterns = ['<script', 'onerror=', 'onload=']
    if any(pattern in note_content.lower() for pattern in xss_patterns):
        if mark_challenge_solved(session['username'], 'stored_xss'):
            flash(f"Congratulations! You solved the Stored XSS challenge! Flag: {FLAGS['stored_xss']}")
    
    # Intentionally vulnerable to XSS - no input sanitization
    conn = get_db()
    c = conn.cursor()
    c.execute("INSERT INTO notes (username, content) VALUES (?, ?)",
              (session['username'], note_content))
    conn.commit()
    conn.close()
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/admin')
def admin_panel():
    # Check if user is logged in first
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    # First check if user is actually admin (through database)
    if not session.get('is_admin'):
        return "Unauthorized - Admin access required", 403
        
    # Then check for token-based vulnerability (intentional)
    if session.get('token', '').startswith('YWRtaW4'):  # base64 of 'admin'
        # Mark session token challenge as solved if accessed through token manipulation
        if not session.get('is_admin') and session.get('logged_in'):
            if mark_challenge_solved(session['username'], 'session_token'):
                flash(f"Congratulations! You solved the Session Token challenge! Flag: {FLAGS['session_token']}")
        
        conn = get_db()
        c = conn.cursor()
        users = c.execute("SELECT username, password, is_admin FROM users").fetchall()
        notes = c.execute("SELECT username, content FROM notes").fetchall()
        conn.close()
        
        # Mark admin panel challenge as solved only when accessing admin panel
        if mark_challenge_solved(session['username'], 'admin_panel'):
            flash(f"Congratulations! You accessed the admin panel! Flag: {FLAGS['admin_panel']}")
        
        return render_template('admin.html', users=users, notes=notes)
    return "Unauthorized", 403

@app.route('/api/check_admin')
def check_admin():
    # Intentionally vulnerable endpoint that reveals admin check logic
    token = request.args.get('token', '')
    is_admin = token.startswith('YWRtaW4')
    
    # Mark hidden info challenge as solved if this endpoint is accessed
    if session.get('logged_in'):
        if mark_challenge_solved(session['username'], 'hidden_info'):
            flash(f"Congratulations! You found a hidden endpoint! Flag: {FLAGS['hidden_info']}")
    
    return jsonify({'is_admin': is_admin})

@app.route('/clear_notes')
def clear_notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    try:
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM notes WHERE username=?", (session['username'],))
        conn.commit()
        conn.close()
        flash("All notes have been cleared!")
    except Exception as e:
        flash(f"Error clearing notes: {str(e)}")
    
    return redirect(url_for('dashboard'))

if __name__ == '__main__':
    init_db()  # Initialize database when starting the app
    app.run(debug=True)  # Debug mode enabled intentionally 