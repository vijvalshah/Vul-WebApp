from flask import Flask, render_template, request, redirect, url_for, session, jsonify, flash, send_from_directory, send_file
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
import json
from urllib.parse import unquote
from functools import wraps
from collections import defaultdict
from werkzeug.utils import safe_join

app = Flask(__name__)
app.secret_key = 'your_secret_key_here'  # Change this to a secure secret key
app.config['PERMANENT_SESSION_LIFETIME'] = 3600  # 1 hour session lifetime

# Rate limiting configuration
RATE_LIMIT_WINDOW = 45  # 45 seconds window
MAX_REQUESTS_PER_WINDOW = 1000  # More generous limit for general requests
MAX_DB_REQUESTS_PER_WINDOW = 50  # Stricter limit for database-creating requests
MAX_BOT_REQUESTS_PER_WINDOW = 100  # Very strict limit for automated tools
BLOCK_DURATION = 60  # Block duration in seconds
REQUEST_BURST_THRESHOLD = 200  # Number of requests in 5 seconds to trigger blocking
MAX_DB_PER_IP = 3  # Maximum databases per IP
MAX_DB_CREATION_RATE = 10  # Maximum new databases per minute
request_counts = defaultdict(lambda: {'count': 0, 'db_count': 0, 'window_start': 0, 'db_creation_time': [], 'bot_count': 0, 'recent_requests': []})
ip_db_counts = defaultdict(int)
blocked_ips = {}  # Store blocked IPs with their block timestamp

# Bot detection settings
SUSPICIOUS_HEADERS = {
    'sqlmap', 'burp', 'x-scanner', 'acunetix', 
    'nikto', 'nessus', 'arachni', 'w3af', 'nmap'
}

# Legitimate service user agents (partial matches)
LEGITIMATE_SERVICES = {
    'render', 'googlebot', 'bingbot', 'chrome-lighthouse',
    'google-cloud', 'aws', 'azure', 'cloudflare', 'akamai',
    'fastly', 'vercel', 'heroku', 'netlify'
}

# Add shared database for automated tools
SHARED_BOT_DB = 'instance/shared_automated_tests.db'

def is_likely_bot():
    """Check if the request is likely from an automated tool"""
    # Check user agent
    user_agent = request.headers.get('User-Agent', '').lower()
    
    # Allow legitimate services
    if any(service in user_agent for service in LEGITIMATE_SERVICES):
        return False
    
    # Check for SQLMap and other testing tools
    if ('sqlmap' in user_agent or 
        any(header[0].lower() in SUSPICIOUS_HEADERS for header in request.headers.items()) or
        not user_agent or 
        'python' in user_agent or 
        'go-http' in user_agent):
        return True
    
    # Check request patterns that indicate automated tools
    if request.args.get('test') or request.args.get('sleep'):
        return True
    
    # Check for missing cookies only if session exists and not from legitimate service
    if not request.cookies and session.get('session_id'):
        # Additional check for legitimate services
        forwarded_for = request.headers.get('X-Forwarded-For')
        real_ip = request.headers.get('X-Real-IP')
        if not (forwarded_for or real_ip):
            return True
    
    return False

def get_real_client_ip():
    """Get the real client IP address when behind a proxy"""
    # First try to get from Render's special header
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip
        
    # Then try X-Forwarded-For
    forwarded_for = request.headers.get('X-Forwarded-For')
    if forwarded_for:
        # Get the first IP in the chain (client's real IP)
        return forwarded_for.split(',')[0].strip()
    
    # Fallback to remote_addr
    return request.remote_addr

def get_rate_limit_key():
    """Get a key for rate limiting (IP address or session ID)"""
    # If we have a session, use that as the key
    if 'session_id' in session:
        return f"session_{session['session_id']}"
    
    # Otherwise use the real client IP
    client_ip = get_real_client_ip()
    return f"ip_{client_ip}"

def can_create_database(key):
    """Check if a client can create a new database"""
    # Use session ID if available, otherwise use IP
    if key.startswith('session_'):
        # Allow only one database per session
        session_id = key.split('_')[1]
        db_path = os.path.join('instance', f'users_{session_id}.db')
        return not os.path.exists(db_path)
    else:
        # For IP-based limits, be more lenient
        ip = key.split('_')[1]
        return ip_db_counts[ip] < MAX_DB_PER_IP

def is_ip_blocked(ip):
    """Check if an IP is currently blocked"""
    if ip in blocked_ips:
        block_time = blocked_ips[ip]
        if time.time() - block_time >= BLOCK_DURATION:
            # Unblock if duration has passed
            del blocked_ips[ip]
            print(f"[Rate Limit] Unblocked IP: {ip} after {BLOCK_DURATION} seconds")
            return False
        return True
    return False

def check_request_burst(ip):
    """Check if there are too many requests in a short time window"""
    current_time = time.time()
    recent_requests = request_counts[ip]['recent_requests']
    
    # Remove requests older than 5 seconds
    recent_requests = [t for t in recent_requests if current_time - t <= 5]
    request_counts[ip]['recent_requests'] = recent_requests
    
    # Add current request
    recent_requests.append(current_time)
    
    # If too many requests in 5 seconds, block the IP
    if len(recent_requests) > REQUEST_BURST_THRESHOLD:
        blocked_ips[ip] = current_time
        print(f"[Rate Limit] BLOCKED IP: {ip} for {BLOCK_DURATION} seconds due to burst traffic ({len(recent_requests)} requests in 5s)")
        return True
    
    return False

def rate_limit():
    """Decorator for rate limiting with different limits for DB and non-DB requests"""
    def decorator(f):
        @wraps(f)
        def wrapped(*args, **kwargs):
            try:
                client_ip = get_real_client_ip()
                
                # Check if IP is blocked - RETURN EARLY
                if is_ip_blocked(client_ip):
                    return jsonify({
                        'error': f'Too many requests. Please wait {BLOCK_DURATION} seconds before trying again.'
                    }), 429
                
                # Check for request bursts - RETURN EARLY
                if check_request_burst(client_ip):
                    return jsonify({
                        'error': f'Too many requests detected. Your IP has been blocked for {BLOCK_DURATION} seconds.'
                    }), 429
                
                key = get_rate_limit_key()
                current_time = time.time()
                
                # Reset window if needed
                if current_time - request_counts[key]['window_start'] >= RATE_LIMIT_WINDOW:
                    request_counts[key] = {
                        'count': 0, 
                        'db_count': 0, 
                        'bot_count': 0,
                        'window_start': current_time,
                        'db_creation_time': request_counts[key].get('db_creation_time', []),
                        'recent_requests': request_counts[key].get('recent_requests', [])
                    }
                
                # Check if it's a bot - STRICT BLOCKING FOR BOTS
                if is_likely_bot():
                    request_counts[key]['bot_count'] += 1
                    # Log high bot activity
                    if request_counts[key]['bot_count'] % 50 == 0:
                        print(f"[Rate Limit] High bot activity from {client_ip}: {request_counts[key]['bot_count']} requests")
                    
                    # Immediately block if exceeding bot request threshold
                    if request_counts[key]['bot_count'] > MAX_BOT_REQUESTS_PER_WINDOW:
                        # Add to blocked IPs
                        blocked_ips[client_ip] = current_time
                        print(f"[Rate Limit] Bot rate limit exceeded for {client_ip}. Blocking for {BLOCK_DURATION} seconds.")
                        return jsonify({
                            'error': 'Rate limit exceeded for automated tools. Please wait before trying again.'
                        }), 429
                else:
                    # Increment request count for normal users
                    request_counts[key]['count'] += 1
                    
                    # For requests that create databases, also track db_count
                    if should_create_database():
                        request_counts[key]['db_count'] += 1
                        # Check if database-creating requests exceeded limit
                        if request_counts[key]['db_count'] > MAX_DB_REQUESTS_PER_WINDOW:
                            # Add to blocked IPs
                            blocked_ips[client_ip] = current_time
                            print(f"[Rate Limit] Database creation limit exceeded for {client_ip}")
                            return jsonify({
                                'error': 'Database creation rate limit exceeded. Please try again later.'
                            }), 429
                    
                    # For general requests, use the more generous limit
                    elif request_counts[key]['count'] > MAX_REQUESTS_PER_WINDOW:
                        # Add to blocked IPs
                        blocked_ips[client_ip] = current_time
                        print(f"[Rate Limit] General request limit exceeded for {client_ip}")
                        return jsonify({
                            'error': 'Rate limit exceeded. Please try again later.'
                        }), 429
                
                return f(*args, **kwargs)
            except Exception as e:
                print(f"Rate limit error: {str(e)}")
                # Don't fall through to the endpoint on errors
                return jsonify({
                    'error': 'Rate limiting error occurred'
                }), 500
        return wrapped
    return decorator

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

def enforce_db_creation_rate(client_ip):
    """Enforce rate limit on database creation"""
    current_time = time.time()
    creation_times = request_counts[f"ip_{client_ip}"]['db_creation_time']
    
    # Remove timestamps older than 1 minute
    creation_times = [t for t in creation_times if current_time - t < 60]
    request_counts[f"ip_{client_ip}"]['db_creation_time'] = creation_times
    
    # Check if too many databases were created in the last minute
    if len(creation_times) >= MAX_DB_CREATION_RATE:
        return False
    
    # Add current timestamp
    creation_times.append(current_time)
    return True

def get_user_db_path(session_id=None):
    """Get database path specific to user's session or shared db for automated tools"""
    # If it's an automated tool, use the shared database
    if is_likely_bot():
        # Initialize shared database if it doesn't exist
        if not os.path.exists(SHARED_BOT_DB):
            init_user_db(SHARED_BOT_DB, 'shared_automated')
        return SHARED_BOT_DB
    
    # For real users, continue with session-specific database
    if session_id is None:
        if 'session_id' not in session:
            client_ip = get_real_client_ip()
            
            # Check database creation rate
            if not enforce_db_creation_rate(client_ip):
                raise Exception("Database creation rate limit exceeded. Please try again later.")
            
            # Check if this IP already has a session/database
            existing_dbs = glob.glob(os.path.join('instance', 'users_*.db'))
            for db in existing_dbs:
                db_session = db.split('users_')[1].replace('.db', '')
                if db_session in session.get('ip_sessions', {}).get(client_ip, []):
                    session['session_id'] = db_session
                    return db
            
            # Additional checks for new database creation
            if len(existing_dbs) > 0:
                newest_db_time = max(os.path.getctime(db) for db in existing_dbs)
                if time.time() - newest_db_time < 2:  # 2 second minimum between creations
                    raise Exception("Creating databases too quickly. Please wait.")
            
            session['session_id'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
            session.permanent = True
            
            # Track this session ID for this IP
            if 'ip_sessions' not in session:
                session['ip_sessions'] = {}
            if client_ip not in session['ip_sessions']:
                session['ip_sessions'][client_ip] = []
            session['ip_sessions'][client_ip].append(session['session_id'])
            
            # Track database creation for this IP
            ip_db_counts[client_ip] = len(session['ip_sessions'][client_ip])
            
        session_id = session['session_id']
    
    db_path = os.path.join('instance', f'users_{session_id}.db')
    return db_path

def init_user_db(db_path, session_id=None):
    """Initialize a new database for a specific session"""
    if session_id is None and 'session_id' in session:
        session_id = session['session_id']
    
    print(f"\nInitializing new database for Session: {session_id}")
    print(f"Creating database at: {db_path}")
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()

    # Create tables
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  is_admin INTEGER DEFAULT 0,
                  preferences TEXT DEFAULT '{}')''')

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

    # Generate random passwords for admin and cabinet
    admin_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    cabinet_password = ''.join(random.choices(string.ascii_letters + string.digits, k=16))
    
    # Initialize admin_passwords in session if it doesn't exist
    if 'admin_passwords' not in session:
        session['admin_passwords'] = {}
    
    # Store admin password for this session
    session['admin_passwords'][session_id] = admin_password

    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('admin', admin_password, 1))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('user', 'password123', 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('Unknown', 'Th3w3eknd15th3be35T', 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('cabinet', cabinet_password, 0))
    c.execute("INSERT OR IGNORE INTO users (username, password, is_admin) VALUES (?, ?, ?)", 
             ('cyscom', '15012022', 0))

    # Add the non-deletable notes
    image_note = '<div style="text-align: center;"><h3>My Darkest Hours</h3><img src="/userdata/88382n2nbd92.png" alt="Different girls on the floor, distractin my thoughts of you" style="max-width: 100%; height: auto;"><p>Girl, I felt so alone inside of this crowded room</p></div>'
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
    c.execute("INSERT OR IGNORE INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
             ('cabinet', 'Remember The Date, When it was created', '<a href="https://cyscomvit.com/">Click Me!</a>', 0))
    c.execute("INSERT OR IGNORE INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
             ('cabinet', 'Attention!','Our main account will be deleted soon since the password was too easy to guess. I mean who uses a date as password? Please inform all members to create new accounts with stronger passwords', 0))

    conn.commit()
    conn.close()

    print(f"Database initialized successfully")
    print(f"Admin password for Session {session_id}: {admin_password}")
    print(f"Cyscom password for Session {session_id}: {cabinet_password}")
    
    # Print current database count
    count_db_files()

def get_db():
    """Connect to the session-specific database"""
    db_path = get_user_db_path()
    
    # Initialize the database if it doesn't exist
    if not os.path.exists(db_path):
        init_user_db(db_path, get_real_client_ip())
    
    db = sqlite3.connect(db_path)
    db.row_factory = sqlite3.Row
    return db

def should_create_database():
    """Check if the current request should create a database"""
    # List of endpoints that require database interaction
    db_required_endpoints = {
        'login', 'dashboard', 'add_note', 'flags', 'admin_panel', 
        'view_note', 'search', 'verify_backup', 'update_preferences'
    }
    
    # List of methods that might need database interaction
    db_required_methods = {'POST', 'PUT', 'DELETE'}
    
    # Always create DB for POST requests to these endpoints
    if request.method in db_required_methods and request.endpoint in db_required_endpoints:
        return True
    
    # For GET requests, only create DB if user is already logged in
    if request.method == 'GET' and session.get('logged_in'):
        return True
    
    # For specific endpoints that need DB even without login
    if request.endpoint in {'login', 'reset_password'}:
        return True
    
    return False

@app.before_request
def enforce_session_persistence():
    """Enforce session persistence and limit database creation"""
    if request.endpoint != 'static' and should_create_database():
        # For automated tools, check rate limit but allow shared database
        if is_likely_bot():
            key = get_rate_limit_key()
            current_time = time.time()
            
            # Reset window if needed
            if current_time - request_counts[key]['window_start'] >= RATE_LIMIT_WINDOW:
                request_counts[key]['bot_count'] = 0
                request_counts[key]['window_start'] = current_time
            
            # Check bot rate limit
            request_counts[key]['bot_count'] = request_counts[key].get('bot_count', 0) + 1
            if request_counts[key]['bot_count'] > MAX_BOT_REQUESTS_PER_WINDOW:
                return jsonify({
                    'error': 'Rate limit exceeded for automated tools. Please slow down your requests.'
                }), 429
            return None
            
        client_ip = get_real_client_ip()
        
        # Initialize session tracking
        if 'ip_sessions' not in session:
            session['ip_sessions'] = {}
            
        # Check if this IP has too many databases
        existing_sessions = session['ip_sessions'].get(client_ip, [])
        if len(existing_sessions) >= MAX_DB_PER_IP and 'session_id' not in session:
            return jsonify({
                'error': 'Too many sessions from this IP. Please complete or close existing sessions.'
            }), 429
        
        # Clean up old sessions periodically
        if len(existing_sessions) > 0:
            valid_sessions = []
            for sess_id in existing_sessions:
                db_path = os.path.join('instance', f'users_{sess_id}.db')
                if os.path.exists(db_path):
                    valid_sessions.append(sess_id)
            session['ip_sessions'][client_ip] = valid_sessions

@app.before_request
@rate_limit()
def before_request():
    """Ensure user's session-specific database exists before each request"""
    # Skip database creation for static files and non-database endpoints
    if request.endpoint == 'static' or not should_create_database():
        return
        
    # First enforce session persistence
    persistence_result = enforce_session_persistence()
    if persistence_result is not None:
        return persistence_result
        
    # Initialize admin_passwords if it doesn't exist
    if 'admin_passwords' not in session:
        session['admin_passwords'] = {}
        
    if 'session_id' not in session:
        rate_limit_key = get_rate_limit_key()
        if not can_create_database(rate_limit_key):
            return jsonify({'error': 'Maximum database limit reached'}), 429
        
        session['session_id'] = ''.join(random.choices(string.ascii_letters + string.digits, k=32))
        session.permanent = True  # Make session permanent
    
    db_path = get_user_db_path(session['session_id'])
    if not os.path.exists(db_path):
        init_user_db(db_path, session['session_id'])
    elif 'username' in session and session.get('is_admin'):
        try:
            conn = get_db()
            c = conn.cursor()
            c.execute("SELECT password FROM users WHERE username='admin'")
            stored_password = c.fetchone()[0]
            session['admin_passwords'][session['session_id']] = stored_password
            conn.close()
        except Exception as e:
            print(f"Error updating admin password in session: {str(e)}")
            if 'conn' in locals():
                conn.close()

@app.route('/')
def index():
    # Only check IP changes if we're creating a database
    if should_create_database():
        current_ip = get_real_client_ip()
        if 'last_ip' in session and session['last_ip'] != current_ip:
            if session['last_ip'].split('.')[0:2] != current_ip.split('.')[0:2]:
                session.clear()
                print(f"Session cleared due to significant IP change: {session['last_ip']} -> {current_ip}")
        session['last_ip'] = current_ip
    
    return render_template('login.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        try:
            # Initialize admin_passwords if it doesn't exist
            if 'admin_passwords' not in session:
                session['admin_passwords'] = {}
            
            conn = get_db()
            if not conn:
                return render_template('login.html', error='Database connection error')
            
            c = conn.cursor()
            
            # Block OR-based SQL injections
            or_patterns = [
                r"(?i)'\s*or\s*'?[0-9a-z]+\s*=\s*'?[0-9a-z]+",  # matches ' OR '1'='1', 'or'a'='a', etc
                r"(?i)'\s*or\s*'.*?'.*?'",      # matches ' OR 'anything'='anything'
                r"(?i)'\s*or\s*true",           # matches ' OR TRUE and variations
                r"(?i)'\s*or\s*1",              # matches ' OR 1 and variations
                r"(?i)'\s*or\s*[0-9]+",         # matches ' OR 2=2 and variations
                r"(?i).*?\bor\b.*?=",           # matches any OR with equals
                r"(?i)'\s*or\s*'",              # matches ' OR ' pattern
            ]
            
            if any(re.search(pattern, username) or re.search(pattern, password) for pattern in or_patterns):
                return render_template('login.html', error='Nice try! OR-based injections are blocked. Try another technique!')
            
            # Check for SQL injection patterns
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
            
            # Intentionally vulnerable to SQL injection (but not OR-based ones)
            query = f"SELECT * FROM users WHERE username='{username}' AND password='{password}'"
            result = c.execute(query).fetchone()

            if result:
                session['logged_in'] = True
                session['username'] = username
                session['token'] = generate_session_token(username)
                session['is_admin'] = bool(result[3])
                
                # Check for SQL injection success
                if is_injection:
                    # Verify it's not a normal login
                    check_c = conn.cursor()
                    normal_query = "SELECT * FROM users WHERE username=? AND password=?"
                    normal_result = check_c.execute(normal_query, (username, password)).fetchone()
                    
                    if not normal_result and mark_challenge_solved(username, 'sql_injection'):
                        flash(f"Congratulations! You solved the SQL Injection challenge! Flag: {FLAGS['sql_injection']}")
                
                # Award privilege escalation flag for legitimate admin login
                if username == 'admin':
                    # Get the current admin password from the database
                    c.execute("SELECT password FROM users WHERE username='admin'")
                    stored_password = c.fetchone()[0]
                    
                    # Store the current admin password in session
                    session['admin_passwords'][session['session_id']] = stored_password
                    
                    if password == stored_password:
                        if mark_challenge_solved(username, 'privilege_escalation'):
                            flash(f"Congratulations! You gained admin access with legitimate credentials! Flag: {FLAGS['privilege_escalation']}")
                
                # If someone logs in as cyscom, grant the osint flag to other accounts
                if username == 'cyscom':
                    try:
                        c.execute(
                            "INSERT OR IGNORE INTO solved_challenges (username, challenge_name) VALUES (?, ?)",
                            ('user', 'osint')
                        )
                        conn.commit()
                        flash("Lost user flag has been granted to all accounts.")
                    except Exception as e:
                        print(f"Error granting osint flag: {e}")
                
                conn.close()
                return redirect(url_for('dashboard'))
            
            conn.close()
            return render_template('login.html', error='Invalid credentials')
            
        except Exception as e:
            # For SQL injection debugging - intentionally reveal error
            return render_template('login.html', error=f'Error: {str(e)}')
    
    return render_template('login.html')

@app.route('/flags')
def flags():
    if not session.get('logged_in'):
        return redirect(url_for('login'))

    if session['username'] == 'cyscom':
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
    if session['username'] == 'cyscom':
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
    """Add a new note with XSS and encoded XSS vulnerabilities"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    title = request.form.get('title', 'Untitled')
    # Check both 'content' and 'note' parameters
    content = request.form.get('content', '') or request.form.get('note', '')
    
    print(f"Debug: Received note - Title: {title}, Content: {content}")
    
    # VULNERABILITY 1: Basic XSS Check
    xss_patterns = ['<script', 'onerror=', 'onload=']
    if any(pattern in content.lower() for pattern in xss_patterns):
        if mark_challenge_solved(session['username'], 'stored_xss'):
            flash(f"Congratulations! You solved the Stored XSS challenge! Flag: {FLAGS['stored_xss']}")
    
    # VULNERABILITY 2: Event-based XSS Check
    event_patterns = [
        'onmouseover=', 'onmouseout=', 'onclick=', 'onload=', 'onerror=',
        'onmouseenter=', 'onmouseleave=', 'onfocus=', 'onblur=', 'onchange=',
        'onkeyup=', 'onkeydown=', 'onkeypress=', 'ondblclick=', 'oncontextmenu=',
        'onmouseup=', 'onmousedown=', 'onsubmit=', 'onreset=', 'onselect=',
        'onabort=', 'ondrag=', 'ondrop=', 'onpaste=', 'oncopy='
    ]
    
    # Check for both regular and encoded event handlers
    encoded_events = [event.replace('on', '%6f%6e') for event in event_patterns]  # URL encoded
    encoded_events.extend([event.replace('on', '&#x6f;&#x6e;') for event in event_patterns])  # HTML hex encoded
    encoded_events.extend([event.replace('on', '&#111;&#110;') for event in event_patterns])  # HTML decimal encoded
    
    all_patterns = event_patterns + encoded_events
    
    # Try to decode content for checking encoded payloads
    try:
        decoded_content = unquote(content)
    except:
        decoded_content = content
    
    # Check both original and decoded content for event-based XSS
    if any(pattern.lower() in content.lower() for pattern in all_patterns) or \
       any(pattern.lower() in decoded_content.lower() for pattern in all_patterns):
        print("Debug: Event-based XSS pattern detected in note")
        if mark_challenge_solved(session['username'], 'event_xss'):
            flash(f"Congratulations! You found the event-based XSS vulnerability! Flag: {FLAGS['event_xss']}")
    
    # VULNERABILITY 3: HTML Entity XSS Bypass
    xss_encoded_patterns = [
        '&#x3c;script', '&#60;script',     # HTML entity encoded
        '&lt;script',                      # Named entity
        '%3Cscript',                       # URL encoded
        '\\x3Cscript',                     # JS hex
        '\\u003Cscript',                   # JS unicode
        '%3Cimg%20src%3Dx%20onerror%3D',
        '&#x3c;img src=x onerror=',
        '&lt;img src=x onerror='
    ]
    
    content_lower = decoded_content.lower()
    original_lower = content.lower()
    
    if any(pattern.lower() in content_lower for pattern in xss_encoded_patterns) or \
       any(pattern.lower() in original_lower for pattern in xss_encoded_patterns):
        print("Debug: Encoded XSS pattern detected")
        if mark_challenge_solved(session.get('username'), 'xss_encoded'):
            flash(f"Congratulations! You found the encoded XSS vulnerability! Flag: {FLAGS['xss_encoded']}")
    
    # VULNERABILITY 4: Template Injection in title
    if '{{' in title and '}}' in title:
        try:
            # If they try to evaluate something sensitive
            if 'config' in title.lower() or 'class' in title.lower():
                if mark_challenge_solved(session.get('username'), 'ssti_advanced'):
                    flash(f"Congratulations! You found the advanced SSTI vulnerability! Flag: {FLAGS['ssti_advanced']}")
        except:
            pass
    
    try:
        # Store the note
        conn = get_db()
        c = conn.cursor()
        c.execute("INSERT INTO notes (username, title, content, is_deletable) VALUES (?, ?, ?, ?)",
                 (session['username'], title, content, 1))
        conn.commit()
        conn.close()
        print(f"Debug: Note saved successfully")
    except Exception as e:
        print(f"Debug: Error saving note: {str(e)}")
        flash("Error saving note: " + str(e))
    
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    """Modified logout to preserve session ID"""
    session_id = session.get('session_id')  # Store session ID before clearing
    session.clear()
    session['session_id'] = session_id  # Restore session ID
    session.permanent = True  # Make session permanent
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

# Secure file serving with whitelisted files and proper path validation
ALLOWED_USERDATA_FILES = {
    '88382n2nbd92.png',
    'internalmeet28-03-2025.wav'
}

@app.route('/userdata/<path:filename>')
def serve_userdata(filename):
    """Serve files from userdata directory with strict security"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Only allow whitelisted files
    if filename not in ALLOWED_USERDATA_FILES:
        return "File not found", 404
    
    try:
        # Use safe_join to prevent path traversal
        safe_path = safe_join('userdata', filename)
        if safe_path is None:  # safe_join returns None if path traversal was attempted
            return "Invalid file path", 400
            
        # Additional path validation
        if not os.path.abspath(safe_path).startswith(os.path.abspath('userdata')):
            return "Invalid file path", 400
            
        return send_file(safe_path)
    except Exception as e:
        print(f"File serving error: {str(e)}")
        return "File not found", 404

@app.route('/discussions')
def discussions():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return render_template('discussions.html')

@app.route('/search', methods=['GET', 'POST'])
def search():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    # Get query from either POST or GET
    query = request.form.get('query', '') or request.args.get('q', '')
    print(f"Debug: Search query received: {query}")
    
    # URL decode the query to handle encoded payloads
    try:
        decoded_query = unquote(query)
    except:
        decoded_query = query
    
    print(f"Debug: Decoded search query: {decoded_query}")
    
    # Check for event-based XSS patterns
    event_patterns = [
        'onmouseover=', 'onmouseout=', 'onclick=', 'onload=', 'onerror=',
        'onmouseenter=', 'onmouseleave=', 'onfocus=', 'onblur=', 'onchange=',
        'onkeyup=', 'onkeydown=', 'onkeypress=', 'ondblclick=', 'oncontextmenu=',
        'onmouseup=', 'onmousedown=', 'onsubmit=', 'onreset=', 'onselect=',
        'onabort=', 'ondrag=', 'ondrop=', 'onpaste=', 'oncopy='
    ]
    
    # Check for both regular and encoded event handlers
    encoded_events = [event.replace('on', '%6f%6e') for event in event_patterns]  # URL encoded
    encoded_events.extend([event.replace('on', '&#x6f;&#x6e;') for event in event_patterns])  # HTML hex encoded
    encoded_events.extend([event.replace('on', '&#111;&#110;') for event in event_patterns])  # HTML decimal encoded
    
    all_patterns = event_patterns + encoded_events
    
    # Check both original and decoded query
    if any(pattern.lower() in query.lower() for pattern in all_patterns) or \
       any(pattern.lower() in decoded_query.lower() for pattern in all_patterns):
        print("Debug: Event-based XSS pattern detected")
        if mark_challenge_solved(session['username'], 'event_xss'):
            flash(f"Congratulations! You found the event-based XSS vulnerability! Flag: {FLAGS['event_xss']}")
    
    # Check for template injection attempts (keep existing SSTI check)
    ssti_patterns = ['{{', '{%', 'config', '__class__', '__globals__']
    if any(pattern in decoded_query for pattern in ssti_patterns):
        if mark_challenge_solved(session['username'], 'ssti'):
            flash(f"Congratulations! You found the Template Injection vulnerability! Flag: {FLAGS['ssti']}")
    
    # Intentionally vulnerable to both XSS and template injection
    template = f'''
        <div class="search-results">
            <h3>Search Results for: {decoded_query}</h3>
            <p>No results found.</p>
        </div>
    '''
    return render_template_string(template)

# Add a GET route for search to handle URL parameters
@app.route('/search.html')
def search_page():
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    return redirect(url_for('search'))

@app.route('/note/<int:note_id>')
def view_note(note_id):
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    conn = get_db()  # This will get the session-specific database
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
        
        # Only allow password resets for 'user' and 'cabinet' accounts
        if username not in ['user', 'cabinet']:
            return jsonify({'status': 'error', 'message': 'Password reset not available for this account'})
        
        # Rest of the function remains the same
        current_date = time.strftime('%d')
        expected_token = base64.b64encode(f"{username}:{current_date}".encode()).decode()
        
        if reset_token == expected_token:
            try:
                conn = get_db()
                c = conn.cursor()
                c.execute("UPDATE users SET password = ? WHERE username = ?", 
                         (new_password, username))
                conn.commit()
                
                c.execute("INSERT INTO solved_challenges (username, challenge_name) VALUES (?, ?)",
                         (username, 'broken_auth'))
                conn.commit()
                conn.close()
                
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

@app.route('/api/v1/verify_backup', methods=['POST'])
def verify_backup():
    """Endpoint vulnerable to type juggling"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    try:
        data = request.get_json()
        if not data:
            print("No JSON data received")
            return jsonify({'status': 'error', 'message': 'No data provided'})
            
        backup_hash = data.get('hash', '')
        backup_id = data.get('id')
        
        print(f"Debug: Received data = {data}")
        print(f"Debug: backup_id = {backup_id} ({type(backup_id)})")
        print(f"Debug: backup_hash = {backup_hash} ({type(backup_hash)})")
        
        # Simple type juggling check
        if backup_id == 123 and isinstance(backup_hash, str) and backup_hash.startswith('0e'):
            print("Debug: Basic checks passed")
            try:
                # This is the vulnerable part - converting string to float
                float_hash = float(backup_hash)
                print(f"Debug: float_hash = {float_hash}")
                if float_hash == 0.0:
                    print("Debug: Hash comparison passed")
                    if mark_challenge_solved(session.get('username'), 'type_juggling'):
                        return jsonify({
                            'status': 'success',
                            'message': f'Congratulations! You found the type juggling vulnerability! Flag: {FLAGS["type_juggling"]}'
                        })
            except ValueError as ve:
                print(f"Debug: Float conversion failed: {ve}")
                
    except Exception as e:
        print(f"Debug: Error in verify_backup: {str(e)}")
    
    return jsonify({'status': 'error', 'message': 'Invalid backup verification'})

@app.route('/api/v1/user/preferences', methods=['POST'])
def update_preferences():
    """Endpoint vulnerable to prototype pollution"""
    if not session.get('logged_in'):
        return redirect(url_for('login'))
    
    try:
        # Get new preferences from request
        new_prefs = request.get_json()
        if not new_prefs:
            return jsonify({'status': 'error', 'message': 'No preferences provided'})
            
        print(f"Debug: Received preferences = {new_prefs}")
        
        # Get the current preferences
        conn = get_db()
        c = conn.cursor()
        
        # Get and parse current preferences
        c.execute("SELECT preferences FROM users WHERE username = ?", (session['username'],))
        result = c.fetchone()
        current_prefs = json.loads(result[0]) if result and result[0] else {}
        
        print(f"Debug: Current preferences = {current_prefs}")
        
        # Check for prototype pollution attempt first
        if '__proto__' in str(new_prefs) or 'constructor' in str(new_prefs):
            print("Debug: Prototype pollution detected")
            if mark_challenge_solved(session['username'], 'proto_pollution'):
                return jsonify({
                    'status': 'success',
                    'message': f'Congratulations! You found the prototype pollution vulnerability! Flag: {FLAGS["proto_pollution"]}'
                })
        
        # Store the new preferences
        c.execute("UPDATE users SET preferences = ? WHERE username = ?", 
                 (json.dumps(new_prefs), session['username']))
        conn.commit()
        conn.close()
        
        return jsonify({'status': 'success', 'message': 'Preferences updated successfully'})
        
    except Exception as e:
        print(f"Debug: Error in update_preferences: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)})

def cleanup_old_databases():
    """Clean up databases older than 1 hour"""
    current_time = time.time()
    
    # Don't clean up the shared bot database
    for db_file in glob.glob(os.path.join('instance', 'users_*.db')):
        if os.path.exists(db_file) and db_file != SHARED_BOT_DB:
            file_age = current_time - os.path.getmtime(db_file)
            if file_age > 3600:  # 1 hour
                try:
                    session_id = db_file.split('users_')[1].replace('.db', '')
                    
                    # Remove from all IP sessions tracking
                    if 'ip_sessions' in session:
                        for ip in session['ip_sessions']:
                            if session_id in session['ip_sessions'][ip]:
                                session['ip_sessions'][ip].remove(session_id)
                    
                    os.remove(db_file)
                    print(f"Cleaned up old database: {db_file}")
                except Exception as e:
                    print(f"Error cleaning up database {db_file}: {str(e)}")
    
    # Reset shared bot database periodically
    if os.path.exists(SHARED_BOT_DB):
        file_age = current_time - os.path.getmtime(SHARED_BOT_DB)
        if file_age > 3600:  # Reset every hour
            try:
                os.remove(SHARED_BOT_DB)
                init_user_db(SHARED_BOT_DB, 'shared_automated')
                print("Reset shared automated testing database")
            except Exception as e:
                print(f"Error resetting shared database: {str(e)}")

# Add rate limiting data cleanup
def cleanup_rate_limit_data():
    """Clean up old rate limiting data"""
    current_time = time.time()
    
    # Clean up request counts and database creation timestamps
    for key in list(request_counts.keys()):
        if current_time - request_counts[key]['window_start'] >= RATE_LIMIT_WINDOW * 2:
            # Keep db_creation_time but remove old timestamps
            creation_times = request_counts[key]['db_creation_time']
            creation_times = [t for t in creation_times if current_time - t < 60]
            if creation_times:
                request_counts[key] = {
                    'count': 0, 
                    'db_count': 0, 
                    'bot_count': 0,
                    'window_start': current_time,
                    'db_creation_time': creation_times,
                    'recent_requests': []
                }
            else:
                del request_counts[key]
    
    # Clean up IP database counts for non-session entries
    for key in list(ip_db_counts.keys()):
        if not key.startswith('session_'):
            ip_db_counts[key] = 0
            
    # Clean up expired blocks
    for ip in list(blocked_ips.keys()):
        if current_time - blocked_ips[ip] >= BLOCK_DURATION:
            del blocked_ips[ip]

# Add periodic cleanup to the application
def init_cleanup_scheduler():
    """Initialize the cleanup scheduler"""
    import threading
    def cleanup_task():
        while True:
            cleanup_old_databases()
            cleanup_rate_limit_data()
            time.sleep(3600)  # Run every hour
    
    cleanup_thread = threading.Thread(target=cleanup_task, daemon=True)
    cleanup_thread.start()

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
    'event_xss': 'Event-Based XSS',
    'admin_panel': 'Admin Panel',
    'hidden_info': 'Hidden Info',
    'idor': 'IDOR',
    'ssti': 'SSTI',
    'osint': 'Lost User',
    'broken_access': 'Broken Access Control',
    'broken_auth': 'Broken Authentication',
    'type_juggling': 'Type Juggling',
    'proto_pollution': 'Prototype Pollution',
    'ssti_advanced': 'Advanced SSTI',
    'xss_encoded': 'Encoded XSS'
}

FLAGS = {
    'sql_injection': 'CYSM{sql_iNj3ct-10n}',
    'privilege_escalation': 'CYSM{pr1v1l3g3@escal}',
    'stored_xss': 'CYSM{S70*Xs5}',
    'event_xss': 'CYSM{3v3nt_b4s3d_Xs5}',
    'admin_panel': 'CYSM{4DMINc0n-s0-1}',
    'hidden_info': 'CYSM{cr4ckedbyWH0?}',
    'idor': 'CYSM{n0t3-Sn1ff3r}',
    'ssti': 'CYSM{T3mPl4t3^1nj3cT10n}',
    'osint': 'CYSM{Th15-4cc0unt-d035nt-3X1St}',
    'broken_access': 'CYSM{Br0k3_my_4cc355_C0ntr0l}',
    'broken_auth': 'CYSM{Br0k3N=P45S_R353t}',
    'type_juggling': 'CYSM{Pyth0n_typ3_juggl1ng_1s_fun}',
    'proto_pollution': 'CYSM{pr0t0_p0llut10n_1n_th3_w1ld}',
    'ssti_advanced': 'CYSM{s5t1_4dv4nc3d_1s_fun}',
    'xss_encoded': 'CYSM{xss_3nc0d3d_1s_fun}'
}

def generate_session_token(username):
    timestamp = str(int(time.time()))
    token = base64.b64encode(f"{username}:{timestamp}".encode()).decode()
    return token

def mark_challenge_solved(username, challenge_name):
    try:
        # Don't store flags for 'om' user
        if username == 'cyscom':
            return True

        conn = get_db()
        c = conn.cursor()
        # Check if already solved for this session (any user)
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
    """Get all solved challenges for the current session (shared across users except 'om')"""
    try:
        # Special handling for 'om' user - only show osint flag
        if username == 'cyscom':
            return ['osint']

        conn = get_db()
        c = conn.cursor()
        # Get all solved challenges for this session regardless of user
        solved = c.execute(
            "SELECT DISTINCT challenge_name FROM solved_challenges"
        ).fetchall()
        return [row[0] for row in solved]
    except Exception as e:
        print(f"Error getting solved challenges: {e}")
        return []
    finally:
        conn.close()

if __name__ == '__main__':
    # Initialize cleanup scheduler
    init_cleanup_scheduler()
    
    # Get port from environment variable or default to 10000
    port = int(os.environ.get('PORT', 10000))
    # Bind to 0.0.0.0 to make it accessible from outside the container
    app.run(host='0.0.0.0', port=port) 