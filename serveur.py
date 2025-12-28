import socket
import threading
import http.server
import urllib.parse
import time
import secrets

PORT_HTTP = 8080
PORT_SOCKS = 1080

# Comptes utilisateurs
USERS = {
    "user1": "pass1",
    "user2": "pass2",
    "admin": "admin123"
}

# Sessions {ip: {"token": str, "expire": timestamp}}
SESSIONS = {}
SESSION_DURATION = 3600  # 1h

###################################
# UTILITAIRES
###################################

def log(msg):
    print(f"[LOG] {time.strftime('%Y-%m-%d %H:%M:%S')} | {msg}")

def is_authenticated(ip, token):
    session = SESSIONS.get(ip)
    if not session:
        return False
    if session["token"] != token:
        return False
    if time.time() > session["expire"]:
        del SESSIONS[ip]
        return False
    return True

def create_session(ip):
    token = secrets.token_hex(16)
    SESSIONS[ip] = {"token": token, "expire": time.time() + SESSION_DURATION}
    return token

###################################
# SERVEUR HTTP
###################################

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def get_token(self):
        cookies = self.headers.get("Cookie")
        if cookies:
            for c in cookies.split(";"):
                if "token=" in c:
                    return c.split("=")[1].strip()
        return None

    def do_GET(self):
        ip = self.client_address[0]
        token = self.get_token()

        if self.path == "/":
            self.path = "/templates/panel.html" if is_authenticated(ip, token) else "/templates/login.html"
        elif self.path == "/panel":
            self.path = "/templates/panel.html" if is_authenticated(ip, token) else "/templates/login.html"
        elif self.path == "/logout":
            if ip in SESSIONS:
                del SESSIONS[ip]
            self.send_response(302)
            self.send_header("Location", "/")
            self.end_headers()
            return

        return http.server.SimpleHTTPRequestHandler.do_GET(self)

    def do_POST(self):
        if self.path == "/login":
            length = int(self.headers.get('Content-Length', 0))
            data = self.rfile.read(length)
            params = urllib.parse.parse_qs(data.decode())

            username = params.get("username", [""])[0]
            password = params.get("password", [""])[0]

            if username in USERS and USERS[username] == password:
                token = create_session(self.client_address[0])
                self.send_response(302)
                self.send_header("Location", "/panel")
                self.send_header("Set-Cookie", f"token={token}; HttpOnly")
                self.end_headers()
                log(f"Connexion réussie: {username} depuis {self.client_address[0]}")
            else:
                self.send_response(302)
                self.send_header("Location", "/")
                self.end_headers()
                log(f"Tentative échouée depuis {self.client_address[0]}")

###################################
# SERVEUR SOCKS5
###################################

def socks_handler(client_sock, client_ip):
    session = SESSIONS.get(client_ip)
    if not session or time.time() > session["expire"]:
        client_sock.close()
        return

    try:
        # Négociation
        client_sock.recv(2)
        client_sock.sendall(b"\x05\x00")  # SOCKS5 sans auth

        # Request
        req = client_sock.recv(4)
        if len(req) < 4 or req[1] != 1:  # CMD CONNECT
            client_sock.close()
            return

        atype = req[3]
        if atype == 1:  # IPv4
            addr = client_sock.recv(4)
            address = ".".join(map(str, addr))
        elif atype == 3:  # Domaine
            length = client_sock.recv(1)[0]
            address = client_sock.recv(length).decode()
        else:
            client_sock.close()
            return

        port_bytes = client_sock.recv(2)
        port = port_bytes[0]*256 + port_bytes[1]

        remote = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        remote.settimeout(6)
        try:
            remote.connect((address, port))
        except:
            client_sock.sendall(b"\x05\x05\x00\x01\x00\x00\x00\x00\x00\x00")  # Fail
            client_sock.close()
            return

        client_sock.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x10\x10")

        # Tunnel
        while True:
            data = client_sock.recv(4096)
            if not data:
                break
            remote.sendall(data)
            resp = remote.recv(4096)
            if not resp:
                break
            client_sock.sendall(resp)

    except Exception as e:
        log(f"Erreur SOCKS: {e}")
    finally:
        client_sock.close()

def start_socks():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("0.0.0.0", PORT_SOCKS))
    s.listen(100)
    log(f"SOCKS5 running on port {PORT_SOCKS}")

    while True:
        client, addr = s.accept()
        threading.Thread(target=socks_handler, args=(client, addr[0]), daemon=True).start()

###################################
# SERVEUR HTTP MULTITHREAD
###################################

class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
    daemon_threads = True

def start_http():
    server = ThreadedHTTPServer(("0.0.0.0", PORT_HTTP), MyHandler)
    log(f"HTTP interface running on port {PORT_HTTP}")
    server.serve_forever()

###################################
# LANCEMENT
###################################

threading.Thread(target=start_socks, daemon=True).start()
start_http()
