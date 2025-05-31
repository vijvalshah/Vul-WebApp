from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory
from flask_sqlalchemy import SQLAlchemy
import sqlite3
import os
import base64
import time
import re
from flask import render_template_string

app = Flask(__name__)
app.secret_key = 'supersecretkey123'  # Intentionally weak secret key

# Vulnerable Database Setup
DATABASE = 'users.db'

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
    'broken_access': 'CYSM{Br0k3_my_4cc355\C0ntr0l}',
    'broken_auth': 'CYSM{Br0k3N=P45S_R353t}'  # Keep flag but remove from visible challenges
}

def init_db():
    try:

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
                     content TEXT NOT NULL,
                     is_deletable BOOLEAN DEFAULT 1)''')
        
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

        # Add new user 'om'
        c.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
                ('om', '210805', False))

        image_note = '<div style="text-align: center;"><h3>My Darkest Hours</h3><img src="/userdata/88382n2nbd92.png" alt="So pour out the gasoline" style="max-width: 100%; height: auto;"><p>Girl, I felt so alone inside of this crowded room</p></div>'
        c.execute("INSERT INTO notes (username, content, is_deletable) VALUES (?, ?, ?)",
                ('Unknown', image_note, False))

        audio_note = '''<div style="text-align: center;">
            <h3>Internal Meeting Recording - Confidential</h3>
            <audio controls style="width: 100%; max-width: 500px;">
                <source src="/userdata/internalmeet28-03-2025.wav" type="audio/wav">
                Your browser does not support the audio element.
            </audio>
            <p style="color: black; margin-top: 10px;">No. The file is not corrupted.</p>
            <p><a href="/userdata/internalmeet28-03-2025.wav" download class="btn btn-primary" style="display: inline-block; padding: 8px 16px; background: #4f46e5; color: white; text-decoration: none; border-radius: 4px; margin-top: 10px;">Download Recording</a></p>
        </div>'''
        c.execute("INSERT INTO notes (username, content, is_deletable) VALUES (?, ?, ?)",
                ('user', audio_note, False))
        
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
    timestamp = str(int(time.time()))
    token = base64.b64encode(f"{username}:{timestamp}".encode()).decode()
    return token

def mark_challenge_solved(username, challenge_name):
    try:
        conn = get_db()
        c = conn.cursor()
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
    c.execute("SELECT id, content FROM notes WHERE username=?", (session['username'],))
    notes = [{'id': row[0], 'content': row[1]} for row in c.fetchall()]
    
    is_admin = session.get('is_admin', False)
    return render_template('dashboard.html', username=session['username'], notes=notes, is_admin=is_admin)

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
    
    conn = get_db()
    c = conn.cursor()
    note = c.execute("SELECT username, content FROM notes WHERE id=?", (note_id,)).fetchone()
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
        
        # Award IDOR flag if accessing another user's note (except Unknown's note)
        if note[0] != session['username']:
            if mark_challenge_solved(session['username'], 'idor'):
                flash(f"Congratulations! You found the IDOR vulnerability! Flag: {FLAGS['idor']}")
        
        return render_template_string('''
            <div style="padding: 20px;">
                <h3>Note Details</h3>
                <p><strong>Author:</strong> {{ note[0] }}</p>
                <div>{{ note[1] | safe }}</div>
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
    init_db()  # Initialize database when starting the app
    app.run(debug=True)  # Debug mode enabled intentionally 