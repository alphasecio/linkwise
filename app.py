import os
import json
import sqlite3
import ipaddress
from datetime import datetime
from functools import wraps
from flask import Flask, request, jsonify, send_from_directory, session
from flask_cors import CORS
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import requests
from bs4 import BeautifulSoup
from google import genai
from google.genai import types
from urllib.parse import urlparse
from dotenv import load_dotenv
from db import init_db, get_db

load_dotenv()

app = Flask(__name__, static_folder='static')
app.config.update({
    'SESSION_COOKIE_SECURE': True,       # only send via HTTPS
    'SESSION_COOKIE_HTTPONLY': True,     # prevent JS access
    'SESSION_COOKIE_SAMESITE': 'Lax',    # or 'Strict' for tighter CSRF defense
})
CORS(app, supports_credentials=True)

secret = os.environ.get("SECRET_KEY")
if not secret:
    raise RuntimeError("SECRET_KEY must be set in environment.")
app.config['SECRET_KEY'] = secret

gemini_api_key = os.environ.get("GEMINI_API_KEY")
if not gemini_api_key:
    raise RuntimeError("GEMINI_API_KEY must be set in environment.")

def safe_url(url):
    """Basic SSRF protection — allow only http/https and block private/internal hosts."""
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        raise ValueError("Invalid URL scheme")
    hostname = parsed.hostname or ''
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local:
            raise ValueError("Access to private/internal IPs not allowed")
    except ValueError:
        # Not an IP; may be a domain
        if hostname.endswith(('.local', '.internal')):
            raise ValueError("Access to local/internal domains not allowed")
    return True

# Initialize Flask-Login
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'index'

@login_manager.unauthorized_handler
def unauthorized():
    # For API calls, return JSON instead of redirecting
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Unauthorized'}), 401
    # Otherwise, fall back to HTML redirect (e.g. root page)
    return send_from_directory('static', 'index.html')

# Initialize the Gemini client with API key
try:
    client = genai.Client(api_key=gemini_api_key)
    print("✓ Gemini API initialized successfully")
except Exception as e:
    raise RuntimeError(f"Failed to initialize Gemini API: {e}")

# Initialize the database
init_db()

# User class for Flask-Login
class User(UserMixin):
    def __init__(self, id, email):
        self.id = id
        self.email = email

@login_manager.user_loader
def load_user(user_id):
    conn = get_db()
    c = conn.cursor()
    c.execute('SELECT id, email FROM users WHERE id = ?', (user_id,))
    user_data = c.fetchone()
    conn.close()
    
    if user_data:
        return User(id=user_data[0], email=user_data[1])
    return None

def extract_article_content(url):
    """Extract article content using BeautifulSoup"""
    try:
        safe_url(url)
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=10)
        response.raise_for_status()

        soup = BeautifulSoup(response.content, 'html.parser')
        for tag in soup(['script', 'style', 'nav', 'header', 'footer', 'aside']):
            tag.decompose()

        # Try article/main
        main_content = soup.find('article') or soup.find('main')

        # Fallback: pick the longest <p>-rich container
        if not main_content:
            candidates = sorted(
                soup.find_all(['div', 'section']),
                key=lambda el: len(el.get_text(strip=True)),
                reverse=True
            )
            main_content = candidates[0] if candidates else soup.body

        text = main_content.get_text(separator=' ', strip=True) if main_content else ''
        title = soup.title.string.strip() if soup.title and soup.title.string else url

        return {'title': title, 'content': text[:5000], 'success': True}
    except Exception as e:
        return {'success': False, 'error': str(e)}

def generate_summary_and_tags(content, title):
    """Generate summary and tags using Gemini"""
    if not client:
        return {
            'summary': 'AI summary unavailable (GEMINI_API_KEY not set)',
            'tags': ['no-api-key']
        }
    
    try:
        prompt = f"""Analyze this article and provide:
1. A concise 2-3 sentence summary
2. 3-5 relevant tags (MUST be single words without spaces, use camelCase if needed)

Title: {title}
Content: {content[:3000]}

Examples of good tags: ["AI", "Technology", "Security", "GoogleCloud", "OpenSource"]
Examples of bad tags: ["Machine Learning", "Cloud Computing", "Web Development"]

Respond ONLY with valid JSON in this exact format (no markdown, no code blocks):
{{
    "summary": "your summary here",
    "tags": ["tag1", "tag2", "tag3"]
}}"""
        
        response = client.models.generate_content(
            model='gemini-2.5-flash',
            contents=prompt
        )
        
        response_text = response.text.strip()
        
        # Remove markdown code blocks if present
        if '```' in response_text:
            # Extract content between code blocks
            parts = response_text.split('```')
            for part in parts:
                part = part.strip()
                if part.startswith('json'):
                    part = part[4:].strip()
                if part.startswith('{') and part.endswith('}'):
                    response_text = part
                    break
        
        result = json.loads(response_text)
        
        # Validate the result
        if 'summary' not in result or 'tags' not in result:
            raise ValueError("Invalid response format - missing summary or tags")
        
        if not isinstance(result['tags'], list):
            raise ValueError("Tags must be a list")
        
        return result
        
    except json.JSONDecodeError as e:
        print(f"JSON decode error: {e}")
        print(f"Raw response: {response.text if 'response' in locals() else 'No response'}")
        # Return a basic summary from the title
        return {
            'summary': f"Article about: {title}",
            'tags': ['article', 'web']
        }
    except Exception as e:
        print(f"Gemini API error: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
        # Return a basic summary from the title
        return {
            'summary': f"Article: {title}",
            'tags': ['saved']
        }

def get_json():
    data = request.get_json(silent=True)
    return data if isinstance(data, dict) else {}

@app.route('/')
def index():
    return send_from_directory('static', 'index.html')

@app.route('/<path:path>')
def serve_static(path):
    return send_from_directory('static', path)

@app.route('/api/signup', methods=['POST'])
def signup():
    """User registration"""
    try:
        data = get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        if len(password) < 6:
            return jsonify({'error': 'Password must be at least 6 characters'}), 400
        
        conn = get_db()
        c = conn.cursor()
        
        # Check if user exists
        c.execute('SELECT id FROM users WHERE email = ?', (email,))
        if c.fetchone():
            conn.close()
            return jsonify({'error': 'Email already registered'}), 400
        
        # Create user
        password_hash = generate_password_hash(password)
        c.execute('INSERT INTO users (email, password_hash) VALUES (?, ?)', 
                  (email, password_hash))
        conn.commit()
        user_id = c.lastrowid
        conn.close()
        
        # Log user in
        user = User(id=user_id, email=email)
        login_user(user)
        
        return jsonify({'success': True, 'email': email})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/signin', methods=['POST'])
def signin():
    """User login"""
    try:
        data = get_json()
        email = data.get('email', '').strip().lower()
        password = data.get('password', '')
        
        if not email or not password:
            return jsonify({'error': 'Email and password required'}), 400
        
        conn = get_db()
        c = conn.cursor()
        c.execute('SELECT id, email, password_hash FROM users WHERE email = ?', (email,))
        user_data = c.fetchone()
        conn.close()
        
        if not user_data or not check_password_hash(user_data[2], password):
            return jsonify({'error': 'Invalid email or password'}), 401
        
        user = User(id=user_data[0], email=user_data[1])
        login_user(user)
        
        return jsonify({'success': True, 'email': email})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/signout', methods=['POST'])
@login_required
def signout():
    """User logout"""
    logout_user()
    return jsonify({'success': True})

@app.route('/api/me', methods=['GET'])
def get_current_user():
    """Get current user info"""
    if current_user.is_authenticated:
        return jsonify({
            'authenticated': True,
            'email': current_user.email
        })
    return jsonify({'authenticated': False})

@app.route('/api/links', methods=['GET'])
@login_required
def get_links():
    """Get all links for current user"""
    try:
        conn = get_db()
        conn.row_factory = sqlite3.Row
        c = conn.cursor()
        
        c.execute('''SELECT id, url, title, summary, tags, created_at 
                     FROM links WHERE user_id = ? 
                     ORDER BY created_at DESC''', (current_user.id,))
        
        links = []

        for row in c.fetchall():
            try:
                tags = json.loads(row['tags']) if row['tags'] else []
            except json.JSONDecodeError:
                tags = []
            links.append({
                'id': row['id'],
                'url': row['url'],
                'title': row['title'],
                'summary': row['summary'],
                'tags': tags,
                'created_at': datetime.fromisoformat(row['created_at']).isoformat() if row['created_at'] else None
            })
        
        conn.close()
        return jsonify({'links': links, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/links', methods=['POST'])
@login_required
def add_link():
    """Add a new link"""
    try:
        data = get_json()
        url = data.get('url', '').strip()
        
        if not url:
            return jsonify({'error': 'URL is required'}), 400
        
        # Extract article content
        article = extract_article_content(url)
        
        if not article['success']:
            return jsonify({'error': 'Failed to extract article content'}), 400
        
        # Generate summary and tags
        ai_result = generate_summary_and_tags(article['content'], article['title'])
        
        # Save to database
        conn = get_db()
        c = conn.cursor()
        
        c.execute('''INSERT INTO links (user_id, url, title, summary, tags) 
                     VALUES (?, ?, ?, ?, ?)''',
                  (current_user.id, url, article['title'], 
                   ai_result['summary'], json.dumps(ai_result['tags'])))
        
        conn.commit()
        link_id = c.lastrowid
        conn.close()
        
        link_data = {
            'id': link_id,
            'url': url,
            'title': article['title'],
            'summary': ai_result['summary'],
            'tags': ai_result['tags'],
            'created_at': datetime.now().isoformat()
        }
        
        return jsonify({'link': link_data, 'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/links/<int:link_id>', methods=['DELETE'])
@login_required
def delete_link(link_id):
    """Delete a link"""
    try:
        conn = get_db()
        c = conn.cursor()
        
        # Verify ownership
        c.execute('SELECT user_id FROM links WHERE id = ?', (link_id,))
        result = c.fetchone()
        
        if not result or int(result[0]) != int(current_user.id):
            conn.close()
            return jsonify({'error': 'Link not found'}), 404
        
        c.execute('DELETE FROM links WHERE id = ?', (link_id,))
        conn.commit()
        conn.close()
        
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 8080))
    app.run(host='0.0.0.0', port=port)
