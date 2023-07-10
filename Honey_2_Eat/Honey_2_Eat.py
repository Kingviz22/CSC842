from http.server import SimpleHTTPRequestHandler, HTTPServer
import logging
import re
# Enable logging to capture statistics
logging.basicConfig(filename='honeypot.log', level=logging.INFO)
class HoneypotRequestHandler(SimpleHTTPRequestHandler):
	def translate_path(self, path):
		# Override the translate_path method to preserve the original path
		return path
	
	def do_GET(self):
		# Log the incoming request
		self.log_request()
		# Emulate a response
		self.send_response(200)
		self.send_header('Content-type', 'text/html')
		self.end_headers()
		self.wfile.write(b"Thank you for visiting the honeypot!")

	def log_request(self, code='-', size='-'):
		# Extract relevant information from the request object
		client_ip = self.client_address[0]
		http_method = self.command
		requested_path = self.path
		user_agent = self.headers.get('User-Agent')
		# Log the information to capture statistics
		log_entry = f"Client IP: {client_ip} | Method: {http_method} | Path: {requested_path} | User-Agent: {user_agent}"
		logging.info(log_entry)
		# Analyze the request and capture statistics for different vulnerability areas
		self.analyze_request()

	def analyze_request(self):
		# Implement logic to analyze different vulnerability areas
		if self.is_sql_injection_attempt():
			logging.info("Detected SQL injection attempt!")
			print("Detected SQL injection attempt!")
		if self.is_xss_attempt():
			logging.info("Detected cross-site scripting (XSS) attempt!")
			print("Detected cross-site scripting (XSS) attempt!")
		if self.is_rce_attempt():
			logging.info("Detected remote code execution (RCE) Attempt!")
			print("Detected remote code execution (RCE) attempt!")
		if self.is_brute_force_attempt():
			logging.info("Detected brute-force attempt!")
			print("Detected brute-force attempt!")
		# Add more analysis logic for other vulnerability areas

	def is_sql_injection_attempt(self):
		# Detect SQL injection attempts by checking for suspicious characters or SQL keywords in request parameters
		suspicious_characters = ["'", "\"", ";", "--","%27","%20","%3D"]
		sql_keywords = ["SELECT", "UNION", "INSERT", "UPDATE", "DELETE", "DROP", "EXEC"]
		query_params = self.path.split('?')[1] if '?' in self.path else ''
		for param in query_params.split('&'):
			param_parts = param.split('=',1)
			if len(param_parts) == 2:
				name, value = param_parts
				for char in suspicious_characters:
					if char in name or char in value:
						return True
				for keyword in sql_keywords:
					if re.search(rf"\b{keyword}\b", name, re.IGNORECASE) or re.search(rf"\b{keyword}\b", value, re.IGNORECASE):
						return True
			return False
		
	def is_xss_attempt(self):
	# Detect cross-site scripting (XSS) attempts by checking for script tags or HTML entities in request parameters
		if '?' not in self.path:
			return False
		for param in self.path.split('?')[1].split('&'):
			param_parts = param.split('=')
			if len(param_parts) == 2:
				name, value = param_parts
				if re.search(r"<script|</script|&lt;script|&lt;/script|script|%3cscript", name, re.IGNORECASE) or \
						re.search(r"<script|</script|&lt;script|&lt;/script|script|%3cscript", value, re.IGNORECASE):
					return True
		return False
	
	def is_rce_attempt(self):
	# Detect remote code execution (RCE) attempts by checking for command execution symbols or known vulnerable endpoints
		if '?' not in self.path:
			return False
		command_execution_symbols = ["|", "`", "$", ";"]
		for param in self.path.split('?')[1].split('&'):
			param_parts = param.split('=')
			if len(param_parts) == 2:
				name, value = param_parts
				for symbol in command_execution_symbols:
					if symbol in name or symbol in value:
						return True
		return False
	
	def is_brute_force_attempt(self):
	# Detect brute-force attempts by checking for repeated login attempts or excessive requests to restricted areas
		if self.path == "/login":
			login_attempts = self.headers.get('username')
			if login_attempts and len(login_attempts) > 3:
				return True
		if self.path == "/admin":
			return True
		return False
	
def run_server():
    server_address = ('0.0.0.0', 80)
    httpd = HTTPServer(server_address, HoneypotRequestHandler)
    print('Honeypot server is running...')
    httpd.serve_forever()
    
if __name__ == '__main__':
    run_server()
