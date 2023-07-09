from flask import Flask, request
import logging
import re

app = Flask(__name__)

# Enable logging to capture statistics
logging.basicConfig(filename='honeypot.log', level=logging.INFO)

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def catch_all(path):
    # Log the incoming request
    log_request(request)
    
    # Emulate a response
    response = "Thank you for visiting the honeypot!"
    return response

def log_request(request):
    # Extract relevant information from the request object
    client_ip = request.remote_addr
    http_method = request.method
    requested_path = request.path
    user_agent = request.headers.get('User-Agent')
    
    # Log the information to capture statistics
    log_entry = f"Client IP: {client_ip} | Method: {http_method} | Path: {requested_path} | User-Agent: {user_agent}"
    logging.info(log_entry)

    # Analyze the request and capture statistics for different vulnerability areas
    analyze_request(request)

def analyze_request(request):
    # Implement logic to analyze different vulnerability areas
    # Here's a simplified example that prints the detected vulnerability type
    
    if is_sql_injection_attempt(request):
        print("Detected SQL injection attempt!")
    
    if is_directory_traversal_attempt(request):
        print("Detected directory traversal attempt!")
    
    if is_xss_attempt(request):
        print("Detected cross-site scripting (XSS) attempt!")
    
    if is_rce_attempt(request):
        print("Detected remote code execution (RCE) attempt!")
    
    if is_brute_force_attempt(request):
        print("Detected brute-force attempt!")
    
    # Add more analysis logic for other vulnerability areas

def is_sql_injection_attempt(request):
    # Detect SQL injection attempts by checking for suspicious characters or SQL keywords in request parameters
    
    suspicious_characters = ["'", "\"", ";", "--"]
    sql_keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC"]

    for param in request.args.values():
        for char in suspicious_characters:
            if char in param:
                return True
        
        for keyword in sql_keywords:
            if re.search(rf"\b{keyword}\b", param, re.IGNORECASE):
                return True
    return False

def is_directory_traversal_attempt(request):
    # Detect directory traversal attempts by checking for "../" or other path manipulation patterns in requested path
    
    path = request.path
    if "../" in path or "..\\" in path:
        return True
    
    return False

def is_xss_attempt(request):
     # Detect cross-site scripting (XSS) attempts by checking for script tags or HTML entities in request parameters
    
    for param in request.args.values():
        if re.search(r"<script|</script|&lt;script|&lt;/script", param, re.IGNORECASE):
            return True
    return False

def is_rce_attempt(request):
    # Detect remote code execution (RCE) attempts by checking for command execution symbols or known vulnerable endpoints
    
    command_execution_symbols = ["|", "`", "$", ";"]
    vulnerable_endpoints = ["/phpinfo.php", "/cgi-bin/", "/shell.php"]

    for param in request.args.values():
        for symbol in command_execution_symbols:
            if symbol in param:
                return True
    
    for endpoint in vulnerable_endpoints:
        if endpoint in request.path:
            return True
    return False

def is_brute_force_attempt(request):
    # Detect brute-force attempts by checking for repeated login attempts or excessive requests to restricted areas
    
    if request.path == "/login":
        login_attempts = request.args.get("username")
        if login_attempts and len(login_attempts) > 3:
            return True
    
    if request.path == "/admin":
        return True
    
    return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=80)