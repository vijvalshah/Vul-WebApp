from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import base64
import time
import re
from flask import render_template_string
from werkzeug.security import generate_password_hash, check_password_hash
import random
import string
from datetime import datetime
import glob
import requests

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key

# Create instance folder if it doesn't exist
if not os.path.exists('instance'):
    os.makedirs('instance')

# Global variable to store admin password for each IP
ip_admin_passwords = {}

def count_db_files():
    """Count and list all database files in instance folder"""
    db_files = glob.glob(os.path.join('instance', 'users_*.db'))
    print(f"\nTotal .db files in instance folder: {len(db_files)}")
    for db_file in db_files:
        print(f"Found database: {db_file}")
    return len(db_files)

def get_real_ip():
    """Get the real client IP address using only ipify"""
    # If we already detected the real IP in this session, use it
    if 'real_ip' in session:
        return session['real_ip']
    
    # Get IP from ipify
    try:
        response = requests.get('https://api.ipify.org?format=json', timeout=3)
        if response.status_code == 200:
            ip = response.json()['ip']
            session['real_ip'] = ip
            print(f"Got real IP {ip} from ipify")
            return ip
    except Exception as e:
        print(f"Failed to get IP from ipify: {str(e)}")
    
    # If ipify fails, use remote_addr as fallback
    ip = request.remote_addr
    session['real_ip'] = ip
    print(f"Using fallback IP: {ip}")
    return ip

def get_user_db_path(ip=None):
    """Get database path specific to user's IP address"""
    if ip is None:
        if request:
            ip = get_real_ip()
        else:
            ip = 'default'
    
    safe_ip = ip.replace('.', '_').replace(':', '_')  # Sanitize IP for filename
    db_path = os.path.join('instance', f'users_{safe_ip}.db')
    print(f"\nAccessing database for IP: {ip}")
    print(f"Database path: {db_path}")
    return db_path

def init_user_db(db_path, ip=None):
    """Initialize a new database for a specific path"""
    if ip is None and request:
        ip = get_real_ip()
    
    print(f"\nInitializing new database for IP: {ip}")
    print(f"Creating database at: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0)''')

    c.execute('''CREATE TABLE IF NOT EXISTS notes
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  title TEXT NOT NULL,
                  content TEXT NOT NULL,
                  is_deletable INTEGER DEFAULT 1)''')

    c.execute('''CREATE TABLE IF NOT EXISTS solved_challenges
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  challenge_name TEXT NOT NULL,
                  solved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')

    # Generate random passwords for admin and cyscom
    admin_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    cyscom_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    # Store admin password for this IP
    if ip:
        ip_admin_passwords[ip] = admin_password

    # Insert users with original passwords for user, unknown, and om
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('admin', admin_password, 1))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('user', 'password123', 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('Unknown', 'Th3w3eknd15th3be35T', 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('cyscom', cyscom_password, 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('om', '210805', 0))

    # Add the non-deletable notes
    image_note = '<div style="text-align: center;"><h3>My Darkest Hours</h3><img src="/userdata/88382n2nbd92.png" alt="So pour out the gasoline" style="max-width: 100%; height: auto;"><p>Girl, I felt so alone inside of this crowded room</p></div>'
    c.execute("INSERT OR IGNORE INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
             ('Unknown', 'Important Notice', image_note, 0))

    audio_note = '''<div style="text-align: center;">
        <h3>Internal Meeting Recording - Confidential</h3>
        <audio controls style="width: 100%; max-width: 500px;">
            <source src="/userdata/internalmeet28-03-2025.wav" type="audio/wav">
            Your browser does not support the audio element.
        </audio>
        <p style="color: black; margin-top: 10px;">No. The file is not corrupted.</p>
        <p><a href="/userdata/internalmeet28-03-2025.wav" download class="btn btn-primary" style="display: inline-block; padding: 8px 16px; background: #4f46e5; color: white; text-decoration: none; border-radius: 4px; margin-top: 10px;">Download Recording</a></p>
    </div>'''
    c.execute("INSERT OR IGNORE INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
             ('user', 'Internal Meeting Recording', audio_note, 0))

    conn.commit()
    conn.close()

    print(f"Database initialized successfully")
    print(f"Admin password for IP {ip}: {admin_password}")
    print(f"Cyscom password for IP {ip}: {cyscom_password}")
    
    # Print current database count
    count_db_files()

def get_db():
    """Connect to the IP-specific database"""
    db_path = get_user_db_path()
    
    # Initialize the database if it doesn't exist
    if not os.path.exists(db_path):
        init_user_db(db_path, get_real_ip())
    
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

@app.before_request
def before_request():
    """Ensure user's IP-specific database exists before each request"""
    if request.endpoint != 'static':  # Skip for static files
        real_ip = get_real_ip()
        db_path = get_user_db_path(real_ip)
        if not os.path.exists(db_path):
            init_user_db(db_path, real_ip)
        elif 'username' in session and session.get('is_admin') and real_ip in ip_admin_passwords:
            # Update admin password in session if it exists for this IP
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username='admin'")
            stored_password = c.fetchone()[0]
            ip_admin_passwords[real_ip] = stored_password
            conn.close()

# Remove default database initialization
if os.path.exists(os.path.join('instance', 'users_default.db')):
    os.remove(os.path.join('instance', 'users_default.db'))

# Print initial database count
print("\nInitial database count:")
count_db_files()

# Flag definitions with challenge display names
CHALLENGE_NAMES = {
    'sql_injection': 'SQL Injection',
    'privilege_escalation': 'Privilege Escalation as Real Admin',
    'stored_xss': 'Stored XSS',
    'admin_panel': 'Admin Panel',
    'hidden_info': 'Hidden Info',
    'idor': 'IDOR',
    'ssti': 'SSTI',
    'osint': 'Lost User',
    'broken_access': 'Broken Access Control',
    'broken_auth': 'Broken Authentication'
}

FLAGS = {
    'sql_injection': 'CYSM{sql_iNj3ct-10n}',
    'privilege_escalation': 'CYSM{pr1v1l3g3@escal}',
    'stored_xss': 'CYSM{S70*Xs5}',
    'admin_panel': 'CYSM{4DMINc0n-s0-1}',
    'hidden_info': 'CYSM{cr4ckedbyWH0?}',
    'idor': 'CYSM{n0t3-Sn1ff3r}',
    'ssti': 'CYSM{T3mPl4t3^1nj3cT10n}',
    'osint': 'CYSM{Th15-4cc0unt-d035nt-3X1St}',
    'broken_access': 'CYSM{Br0k3_my_4cc355_C0ntr0l}',
    'broken_auth': 'CYSM{Br0k3N=P45S_R353t}'
}

def generate_session_token(username):
    timestamp = str(int(time.time()))
    token = base64.b64encode(f"{username}:{timestamp}".encode()).decode()
    return token

def mark_challenge_solved(username, challenge_name):
    """Mark a challenge as solved for the current IP (shared across users except 'om')"""
    try:
        # Don't store flags for 'om' user
        if username == 'om':
            return True

        conn = get_db()
        c = conn.cursor()
        # Check if already solved for this IP (any user)
        result = c.execute(
            "SELECT id FROM solved_challenges WHERE challenge_name=?",
            (challenge_name,)
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
    """Get all solved challenges for the current IP (shared across users except 'om')"""
    try:
        # Special handling for 'om' user - only show osint flag
        if username == 'om':
            return ['osint']

        conn = get_db()
        c = conn.cursor()
        # Get all solved challenges for this IP regardless of user
        solved = c.execute(
            "SELECT DISTINCT challenge_name FROM solved_challenges"
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
                
                # Award privilege escalation flag for legitimate admin login
                real_ip = get_real_ip()
                if session['is_admin'] and username == 'admin' and password == ip_admin_passwords.get(real_ip):
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
    
    # Special handling for 'om' account
    if session['username'] == 'om':
        return render_template_string('''
            <div style="max-width: 800px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #4f46e5; margin-bottom: 1rem;">🏆 Solved Challenges</h2>
                <div style="background: #f3f4f6; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem;">
                    <div style="border: 1px solid #d1d5db; border-radius: 0.375rem; padding: 1rem; margin-bottom: 1rem;">
                        <h3 style="color: #374151; font-size: 1.1rem; margin-bottom: 0.5rem;">Lost User</h3>
                        <p style="color: #6b7280; font-family: monospace; background: #e5e7eb; padding: 0.5rem; border-radius: 0.25rem;">
                            {{ flag }}
                        </p>
                    </div>
                </div>
                <div style="display: flex; gap: 1rem;">
                    <a href="/dashboard" style="text-decoration: none; padding: 0.5rem 1rem; background: #4f46e5; color: white; border-radius: 0.375rem;">Back to Dashboard</a>
                    <a href="/logout" style="text-decoration: none; padding: 0.5rem 1rem; background: #ef4444; color: white; border-radius: 0.375rem;">Logout</a>
                </div>
            </div>
        ''', flag=FLAGS['osint'])
    
    # Get solved challenges for other accounts
    solved_challenges = get_solved_challenges(session['username'])
    return render_template('flags.html', 
                         username=session['username'],
                         solved_challenges=solved_challenges,
                         flags=FLAGS,
                         challenge_names=CHALLENGE_NAMES)

@app.route('/dashboard')
def dashboard():
    if 'username' not in session:
        return redirect(url_for('login'))
    
    # Special handling for 'om' account
    if session['username'] == 'om':
        return render_template_string('''
            <div style="max-width: 800px; margin: 2rem auto; padding: 2rem; background: #fff; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1);">
                <h2 style="color: #4f46e5; margin-bottom: 1rem;">Account Status: Scheduled for Deletion</h2>
                <div style="background: #f3f4f6; padding: 1.5rem; border-radius: 0.5rem; margin-bottom: 1.5rem;">
                    <p style="color: #374151; margin-bottom: 1rem;">
                        This account was marked for deletion by user request on 28-03-2024.
                        All notes and files have been removed as per deletion protocol. You can still view the flags this account has solved.
                    </p>
                    <p style="color: #6b7280;">
                        Account will be permanently removed from our systems within 30 days.
                    </p>
                </div>
                <div style="display: flex; gap: 1rem;">
                    <a href="/flags" style="text-decoration: none; padding: 0.5rem 1rem; background: #4f46e5; color: white; border-radius: 0.375rem;">View Flags</a>
                    <a href="/logout" style="text-decoration: none; padding: 0.5rem 1rem; background: #ef4444; color: white; border-radius: 0.375rem;">Logout</a>
                </div>
            </div>
        ''')
    
    db = get_db()
    c = db.cursor()
    c.execute("SELECT id, title, content FROM notes WHERE username=?", (session['username'],))
    notes = [{'id': row[0], 'title': row[1], 'content': row[2]} for row in c.fetchall()]
    db.close()
    
    is_admin = session.get('is_admin', False)
    return render_template('dashboard.html', username=session['username'], notes=notes, is_admin=is_admin)

@app.route('/add_note', methods=['POST'])
def add_note():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    title = request.form.get('title', 'Untitled')  # Get title with default value
    note_content = request.form.get('note', '')
    
    # Check for XSS attempt - intentionally vulnerable
    xss_patterns = ['<script', 'onerror=', 'onload=']
    if any(pattern in note_content.lower() for pattern in xss_patterns):
        if mark_challenge_solved(session['username'], 'stored_xss'):
            flash(f"Congratulations! You solved the Stored XSS challenge! Flag: {FLAGS['stored_xss']}")
    
    # Intentionally vulnerable to XSS - no input sanitization
    conn = get_db()  # This will get the IP-specific database
    c = conn.cursor()
    c.execute("INSERT INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
              (session['username'], title, note_content, 1))
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

    # Check if user is actually admin
    if not session.get('is_admin'):
        return "Unauthorized - Admin access required", 403
    
    conn = get_db()
    c = conn.cursor()
    users = c.execute("SELECT username, password, is_admin FROM users").fetchall()
    conn.close()
    
    # Mark admin panel challenge as solved only when accessing admin panel
    if mark_challenge_solved(session['username'], 'admin_panel'):
        flash(f"Congratulations! You accessed the admin panel! Flag: {FLAGS['admin_panel']}")
    
    return render_template('admin.html', users=users)

@app.route('/docs')
def docs():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    if not session.get('is_admin'):
        return "Unauthorized - Admin access required", 403
    return render_template('docs.html')

@app.route('/api/v1/users')
def api_users():
    return jsonify({'error': 'Endpoint deprecated for security reasons'}), 403

@app.route('/api/v1/backup')
def api_backup():
    token = request.args.get('token', '')
    
    # Check if token is base64 encoded
    try:
        decoded_token = base64.b64decode(token).decode('utf-8')
        username, timestamp = decoded_token.split(':')
        
        if username == 'admin':
            # Mark the hidden info challenge as solved if user is logged in
            if session.get('logged_in'):
                if mark_challenge_solved(session['username'], 'hidden_info'):
                    flash(f"Congratulations! You found the hidden backup endpoint! Flag: {FLAGS['hidden_info']}")
            
            return render_template('backup_response.html', 
                                success=True,
                                flag=FLAGS['hidden_info'])
    except:
        pass
    
    return render_template('backup_response.html',
                         success=False,
                         error_message="Invalid backup token.")

@app.route('/api/v1/debug')
def api_debug():
    return jsonify({'error': 'Debug mode disabled in production'}), 503

@app.route('/api/v1/internal/users', methods=['GET'])
def internal_users_api():
    # Intentionally vulnerable - no authentication check
    # This endpoint is supposed to be internal only but is publicly accessible
    try:
        conn = get_db()
        c = conn.cursor()
        users = c.execute("SELECT username, is_admin FROM users").fetchall()
        conn.close()
        
        # If accessed, award the broken access control flag
        if session.get('logged_in'):
            if mark_challenge_solved(session['username'], 'broken_access'):
                flash(f"Congratulations! You found the unprotected internal API! Flag: {FLAGS['broken_access']}")
        
        return jsonify({
            'status': 'success',
            'message': 'Internal API - Restricted Access Only',
            'users': [{'username': user[0], 'is_admin': bool(user[1])} for user in users]
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

# Add route to serve files from userdata directory
@app.route('/userdata/<path:filename>')
def serve_userdata(filename):
    # Intentionally vulnerable to path traversal
    # Players can use ../ to access files outside userdata directory
    filepath = os.path.join('userdata', filename)
    if os.path.exists(filepath):
        return send_from_directory('userdata', filename)
    return "File not found", 404

@app.route('/discussions')
def discussions():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('discussions.html')

@app.route('/search', methods=['POST'])
def search():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    query = request.form.get('query', '')
    
    # Check for template injection attempts
    ssti_patterns = ['{{', '{%', 'config', '__class__', '__globals__']
    if any(pattern in query for pattern in ssti_patterns):
        if mark_challenge_solved(session['username'], 'ssti'):
            flash(f"Congratulations! You found the Template Injection vulnerability! Flag: {FLAGS['ssti']}")
    
    # Intentionally vulnerable to template injection
    # Players can inject Jinja2 template syntax
    template = f'''
        <div class="search-results">
            <h3>Search Results for: {query}</h3>
            <p>No results found.</p>
        </div>
    '''
    return render_template_string(template)

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db()  # This will get the IP-specific database
    c = conn.cursor()
    note = c.execute("SELECT username, title, content FROM notes WHERE id=?", (note_id,)).fetchone()
    conn.close()
    
    if note:
        # Special handling for Unknown user's note
        if note[0] == 'Unknown':
            return render_template_string('''
                <div style="padding: 20px;">
                    <h3>Note Details</h3>
                    <p><strong>Author:</strong> {{ note[0] }}</p>
                    <div style="background: #f3f4f6; padding: 1rem; border-radius: 0.5rem;">
                        <p style="color: #6b7280; text-align: center;">
                            🔒 This note has been encrypted by user request.
                        </p>
                    </div>
                    <br>
                    <a href="/dashboard" class="btn">Back to Dashboard</a>
                </div>
            ''', note=note)
        
        # IDOR vulnerability - intentionally not checking if the note belongs to current user
        if note[0] != session['username']:
            if mark_challenge_solved(session['username'], 'idor'):
                flash(f"Congratulations! You found the IDOR vulnerability! Flag: {FLAGS['idor']}")
        
        return render_template_string('''
            <div style="padding: 20px;">
                <h3>Note Details</h3>
                <p><strong>Author:</strong> {{ note[0] }}</p>
                <p><strong>Title:</strong> {{ note[1] }}</p>
                <div>{{ note[2] | safe }}</div>
                <br>
                <a href="/dashboard" class="btn">Back to Dashboard</a>
            </div>
        ''', note=note)
    
    return "Note not found", 404

@app.route('/reset_password', methods=['POST'])
def reset_password():
    try:
        data = request.get_json() if request.is_json else request.form
        username = data.get('username')
        new_password = data.get('new_password')
        reset_token = data.get('token')
        
        # Only allow password resets for 'user' and 'cyscom' accounts
        if username not in ['user', 'cyscom']:
            return jsonify({'status': 'error', 'message': 'Password reset not available for this account'})
        
        # Intentionally vulnerable - predictable reset token
        # Token is just base64(username:DD) where DD is the current date
        current_date = time.strftime('%d')  # Gets current day of month (01-31)
        expected_token = base64.b64encode(f"{username}:{current_date}".encode()).decode()
        
        if reset_token == expected_token:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password = ? WHERE username = ?", 
                         (new_password, username))
                conn.commit()
                
                # Mark challenge as solved for the user whose password was reset
                c.execute("INSERT INTO solved_challenges (username, challenge_name) VALUES (?, ?)",
                         (username, 'broken_auth'))
                conn.commit()
                conn.close()
                
                # Return success with flag
                return jsonify({
                    'status': 'success', 
                    'message': f'Password updated successfully! You found the authentication vulnerability! Flag: {FLAGS["broken_auth"]}'
                })
            except Exception as e:
                return jsonify({'status': 'error', 'message': str(e)})
        
        return jsonify({'status': 'error', 'message': 'Invalid reset token'})
    except Exception as e:
        return jsonify({'status': 'error', 'message': str(e)})

@app.route('/clear_notes')
def clear_notes():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM notes WHERE username=? AND is_deletable=1", (session['username'],))
    conn.commit()
    conn.close()
    
    flash("All deletable notes have been cleared!")
    return redirect(url_for('dashboard'))

@app.route('/about')
def about():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    return render_template('about.html')

if __name__ == '__main__':
    app.run(debug=True)  # Debug mode enabled intentionally 