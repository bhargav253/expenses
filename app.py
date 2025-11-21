from flask import Flask, render_template, redirect, url_for, session, request, jsonify, flash, make_response
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from extensions import db
from authlib.integrations.flask_client import OAuth
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
import os
from datetime import datetime
import json
import requests
import uuid
import logging
import sys
import inspect
import magic
import re
import json
import html
from logging.handlers import RotatingFileHandler
from security_utils import decrypt_str, encrypt_str, encryption_enabled
from dotenv import load_dotenv

# Security Configuration
# ======================

# Rate Limiting Configuration
RATE_LIMITS = {
    'pdf_upload': os.environ.get('PDF_UPLOAD_RATE_LIMIT', '5/minute'),
    'ai_processing': os.environ.get('AI_PROCESSING_RATE_LIMIT', '10/minute'),
    'login': os.environ.get('LOGIN_RATE_LIMIT', '100/minute'),  # Increased for testing
    'general_api': os.environ.get('GENERAL_API_RATE_LIMIT', '100/hour')
}

# File Upload Security
MAX_FILE_SIZE_MB = int(os.environ.get('MAX_FILE_SIZE_MB', '10'))
MAX_FILE_SIZE_BYTES = MAX_FILE_SIZE_MB * 1024 * 1024

# Load environment variables from .env for local development
load_dotenv()

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", None)

# Initialize Flask-Limiter
limiter = Limiter(
    app=app,
    key_func=get_remote_address,
    default_limits=[RATE_LIMITS['general_api']]
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Determine if we're in development mode
# Check multiple environment variables for development mode detection
is_development = (
    os.environ.get('FLASK_ENV') == 'development' or 
    os.environ.get('ENVIRONMENT') == 'development' or
    os.environ.get('FLASK_DEBUG') == '1' or
    (os.environ.get('FLASK_ENV') is None and __name__ == '__main__')
)

# Configure secure cookies based on environment
app.config.update(
    SESSION_COOKIE_SECURE=not is_development,  # HTTPS only in production
    SESSION_COOKIE_HTTPONLY=True,              # No JavaScript access (always enabled for security)
    SESSION_COOKIE_SAMESITE='Lax'              # CSRF protection
)

# Enforce SECRET_KEY presence in non-development environments
if not app.secret_key and not is_development:
    raise RuntimeError("SECRET_KEY must be set in production environments")
elif not app.secret_key:
    app.secret_key = "dev-secret-key-change-in-production"

# Initialize Flask-Talisman for security headers
talisman_config = {
    'content_security_policy': {
        'default-src': "'self'",
        'script-src': ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net", "https://code.jquery.com", "https://cdn.datatables.net"],
        'style-src': ["'self'", "'unsafe-inline'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
        'img-src': ["'self'", "data:", "https:"],
        'font-src': ["'self'", "https://cdnjs.cloudflare.com", "https://cdn.jsdelivr.net"],
        'connect-src': ["'self'"]
    },
    'content_security_policy_nonce_in': ['script-src'],
    'frame_options': 'DENY',
    'referrer_policy': 'strict-origin-when-cross-origin'
}

# Only enable strict security features in production
if not is_development:
    talisman_config.update({
        'force_https': True,
        'session_cookie_secure': True,
        'strict_transport_security': True,
        'strict_transport_security_max_age': 31536000
    })
else:
    # Development settings
    talisman_config.update({
        'force_https': False,
        'session_cookie_secure': False,
        'strict_transport_security': False
    })

talisman = Talisman(app, **talisman_config)

# Structured Logging Setup
# ========================

class SecurityFilter(logging.Filter):
    """Filter to redact sensitive information from logs"""
    
    def filter(self, record):
        # Redact sensitive data from log messages
        if hasattr(record, 'msg'):
            record.msg = self.redact_sensitive_data(record.msg)
        return True
    
    def redact_sensitive_data(self, message):
        """Redact sensitive information from log messages"""
        if not isinstance(message, str):
            return message
        
        # Redact API keys
        message = re.sub(r'(api[_-]?key["\']?\s*:\s*["\']?)([^"\'\s]+)', r'\1[REDACTED]', message, flags=re.IGNORECASE)
        message = re.sub(r'(authorization["\']?\s*:\s*["\']?)(bearer\s+[^"\'\s]+)', r'\1[REDACTED]', message, flags=re.IGNORECASE)
        message = re.sub(r'(password["\']?\s*:\s*["\']?)([^"\'\s]+)', r'\1[REDACTED]', message, flags=re.IGNORECASE)
        message = re.sub(r'(secret["\']?\s*:\s*["\']?)([^"\'\s]+)', r'\1[REDACTED]', message, flags=re.IGNORECASE)
        
        return message

class JSONFormatter(logging.Formatter):
    """Custom JSON formatter for structured logging"""
    
    def format(self, record):
        log_entry = {
            'level': record.levelname,
            'message': record.getMessage(),
            'file': record.pathname,
            'line': record.lineno,
            'function': record.funcName,
            'timestamp': datetime.now().isoformat()
        }
        
        # Add user context if available
        if hasattr(record, 'user_id'):
            log_entry['user_id'] = record.user_id
        if hasattr(record, 'dashboard_id'):
            log_entry['dashboard_id'] = record.dashboard_id
        
        # Add error type for exceptions
        if record.exc_info:
            log_entry['error_type'] = record.exc_info[0].__name__
        
        return json.dumps(log_entry)

def setup_logging():
    """Configure structured logging with file rotation"""
    # Create logs directory if it doesn't exist
    os.makedirs('logs', exist_ok=True)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.INFO)
    
    # Remove existing handlers
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # File handler with rotation
    file_handler = RotatingFileHandler(
        'logs/app.log',
        maxBytes=10*1024*1024,  # 10MB
        backupCount=7,          # Keep 7 days of logs
        encoding='utf-8'
    )
    
    # Apply JSON formatter and security filter
    file_handler.setFormatter(JSONFormatter())
    file_handler.addFilter(SecurityFilter())
    
    # Console handler for development
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(JSONFormatter())
    console_handler.addFilter(SecurityFilter())
    
    # Add handlers
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)

# Initialize logging
setup_logging()
logger = logging.getLogger(__name__)


@app.after_request
def set_csrf_cookie(response):
    """Ensure a fresh CSRF token is available to the client."""
    try:
        csrf_token = generate_csrf()
        response.set_cookie(
            "csrf_token",
            csrf_token,
            secure=not is_development,
            httponly=False,  # Must be readable by JS for fetch headers
            samesite="Lax"
        )
    except Exception as exc:  # pragma: no cover - defensive log path
        logger.error(f"Failed to set CSRF cookie: {exc}")
    return response


@app.errorhandler(CSRFError)
def handle_csrf_error(e):
    if request.accept_mimetypes.accept_json and not request.accept_mimetypes.accept_html:
        return jsonify({'error': 'CSRF validation failed'}), 400
    return make_response(render_template('csrf_error.html', reason=e.description), 400)


@app.context_processor
def inject_security_tokens():
    return {'csrf_token': generate_csrf}

# Security Helper Functions
# =========================

def validate_file_upload(file_data, filename, allowed_mime_types=['application/pdf', 'text/csv', 
                                                                 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
                                                                 'application/vnd.ms-excel']):
    """Validate file upload for security"""
    
    # Check file size
    if len(file_data) > MAX_FILE_SIZE_BYTES:
        raise ValueError(f"File too large. Maximum size is {MAX_FILE_SIZE_MB}MB")
    
    # Check file extension
    allowed_extensions = ['.pdf', '.csv', '.xlsx', '.xls']
    file_ext = os.path.splitext(filename)[1].lower()
    if file_ext not in allowed_extensions:
        raise ValueError(f"Unsupported file type. Allowed: {', '.join(allowed_extensions)}")
    
    # MIME type validation using python-magic
    try:
        mime_type = magic.from_buffer(file_data[:1024], mime=True)
        if mime_type not in allowed_mime_types:
            raise ValueError(f"Invalid file type detected: {mime_type}")
    except Exception as e:
        logger.warning(f"MIME type validation failed: {e}")
        # Fallback to extension-based validation if MIME detection fails
        pass
    
    # Additional security checks
    # Prevent path traversal in filename
    if '..' in filename or '/' in filename or '\\' in filename:
        raise ValueError("Invalid filename")
    
    return True

def sanitize_csv_for_export(csv_data):
    """Sanitize CSV data to prevent formula injection"""
    lines = csv_data.split('\n')
    sanitized_lines = []
    
    for line in lines:
        cells = line.split(',')
        sanitized_cells = []
        
        for cell in cells:
            # Remove quotes for processing
            cell_content = cell.strip().strip('"\'')
            
            # Check for formula injection patterns
            if cell_content.startswith(('=', '+', '-', '@')):
                # Prefix with apostrophe to neutralize formula
                sanitized_cell = "'" + cell_content
            else:
                sanitized_cell = cell_content
            
            # Re-add quotes if needed
            if ',' in sanitized_cell or '"' in sanitized_cell:
                sanitized_cell = '"' + sanitized_cell.replace('"', '""') + '"'
            
            sanitized_cells.append(sanitized_cell)
        
        sanitized_lines.append(','.join(sanitized_cells))
    
    return '\n'.join(sanitized_lines)

def validate_expense_data(expense_data):
    """Validate expense data from Handsontable edits"""
    required_fields = ['date', 'description', 'amount']
    valid_categories = ['car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 
                       'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 
                       'service', 'shopping', 'transport', 'utility', 'vacation']
    
    # Check required fields
    for field in required_fields:
        if field not in expense_data or not expense_data[field]:
            raise ValueError(f"Missing required field: {field}")
    
    # Validate date format
    try:
        datetime.strptime(expense_data['date'], '%Y-%m-%d')
    except ValueError:
        raise ValueError("Invalid date format. Use YYYY-MM-DD")
    
    # Validate amount
    try:
        amount = float(expense_data['amount'])
        if amount <= 0:
            raise ValueError("Amount must be positive")
    except (ValueError, TypeError):
        raise ValueError("Invalid amount format")
    
    # Validate category
    category = expense_data.get('category', 'misc').lower()
    if category not in valid_categories:
        raise ValueError(f"Invalid category. Must be one of: {', '.join(valid_categories)}")
    
    # Sanitize description to prevent XSS
    description = expense_data['description']
    sanitized_description = html.escape(description, quote=True)
    expense_data['description'] = sanitized_description
    
    return expense_data

# AI Model Configuration
AI_MODELS = {
    'deepseek': {
        'name': 'DeepSeek',
        'api_url': 'https://api.deepseek.com/v1/chat/completions',
        'model_name': 'deepseek-chat',
        'api_key_field': 'deepseek_api_key'
    },
    'mistral': {
        'name': 'Mistral',
        'api_url': 'https://api.mistral.ai/v1/chat/completions',
        'model_name': 'mistral-large-latest',
        'api_key_field': 'mistral_api_key'
    },
    'openai': {
        'name': 'OpenAI',
        'api_url': 'https://api.openai.com/v1/chat/completions',
        'model_name': 'gpt-4',
        'api_key_field': 'openai_api_key'
    }
}

# Database configuration
# Prefer DATABASE_URL / SQLALCHEMY_DATABASE_URI env vars; default to local SQLite
database_url = os.environ.get('DATABASE_URL') or os.environ.get('SQLALCHEMY_DATABASE_URI')
# Render/Neon sometimes use postgres://; SQLAlchemy expects postgresql://
if database_url and database_url.startswith('postgres://'):
    database_url = database_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///expenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
oauth = OAuth(app)

# OAuth configuration
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    # Correct well-known OpenID configuration URL (hyphenated)
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Import models
from models import User, Dashboard, DashboardMember, Expense, Category, UploadedFile, ChatSession, DashboardInvitation, UserDashboardSettings, PDFExtraction

# Initialize database tables
def init_db():
    with app.app_context():
        db.create_all()
        logger.info("Database tables created successfully")

# Create tables on startup
init_db()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('dashboard_list'))
    return render_template('index.html')

# Username/Password Authentication
@app.route('/login', methods=['GET', 'POST'])
@limiter.limit(RATE_LIMITS['login'])
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')
        
        # Try to find user by email first, then by username
        user = User.query.filter_by(email=username_or_email).first()
        if not user:
            user = User.query.filter_by(username=username_or_email).first()
        
        if user and user.check_password(password):
            session['user_id'] = user.id
            session['user'] = {
                'id': user.id,
                'email': user.email,
                'name': user.name,
                'picture': user.get_profile_picture()
            }
            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_list'))
        else:
            flash('Invalid username/email or password', 'danger')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        username = request.form.get('username')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')
        
        # Validation
        if password != confirm_password:
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        if User.query.filter_by(email=email).first():
            flash('Email already registered', 'danger')
            return render_template('register.html')
        
        if username and User.query.filter_by(username=username).first():
            flash('Username already taken', 'danger')
            return render_template('register.html')
        
        # Create user
        user = User(
            email=email,
            name=name,
            username=username or email.split('@')[0]
        )
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        flash('Account created successfully! Please login.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/google-login')
def google_login():
    redirect_uri = url_for('auth_callback', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth/callback')
def auth_callback():
    token = google.authorize_access_token()
    
    # Fetch profile information using the UserInfo endpoint; fall back to ID token payload.
    user_info = None
    resp = google.get('https://openidconnect.googleapis.com/v1/userinfo')
    if resp and resp.ok:
        user_info = resp.json()
    else:
        try:
            user_info = google.parse_id_token(token, nonce=token.get('nonce'))
        except TypeError:
            # Authlib may require a nonce; ignore and proceed without ID token parsing.
            user_info = None
    
    if user_info:
        # Store user in session
        # Create or update user in database
        user = User.query.filter_by(google_id=user_info['sub']).first()
        if not user:
            user = User(
                google_id=user_info['sub'],
                email=user_info['email'],
                name=user_info['name'],
                profile_picture=user_info['picture']
            )
            db.session.add(user)
            db.session.commit()
        
        # Update session with model-backed picture (uses default avatar if missing)
        session['user'] = {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'picture': user.get_profile_picture()
        }
        
        session['user_id'] = user.id
        
    return redirect(url_for('dashboard_list'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
def dashboard_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    user_dashboards = DashboardMember.query.filter_by(user_id=user_id).all()
    dashboards = [member.dashboard for member in user_dashboards]
    
    # Get pending invitations for the current user
    pending_invitations = DashboardInvitation.query.filter_by(
        invited_user_id=user_id,
        status='pending'
    ).all()
    
    return render_template('dashboard_list.html', 
                         dashboards=dashboards, 
                         pending_invitations=pending_invitations)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('settings.html', user=user)

@app.route('/api/settings/update-ai-settings', methods=['POST'])
def update_ai_settings():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user = User.query.get(session['user_id'])
    
    # Update default AI provider
    if 'default_ai_provider' in data:
        user.default_ai_provider = data['default_ai_provider']
    
    # Update API keys
    if 'mistral_api_key' in data:
        user.set_encrypted_api_key('mistral_api_key', data['mistral_api_key'])
    if 'openai_api_key' in data:
        user.set_encrypted_api_key('openai_api_key', data['openai_api_key'])
    if 'anthropic_api_key' in data:
        user.set_encrypted_api_key('anthropic_api_key', data['anthropic_api_key'])
    if 'deepseek_api_key' in data:
        user.set_encrypted_api_key('deepseek_api_key', data['deepseek_api_key'])
    
    db.session.commit()
    
    return jsonify({'message': 'AI settings updated successfully'})

@app.route('/api/dashboard/create', methods=['POST'])
def create_dashboard():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user_id = session['user_id']
    
    if not data.get('name'):
        return jsonify({'error': 'Dashboard name is required'}), 400
    
    # Create dashboard
    dashboard = Dashboard(
        name=data['name'],
        description=data.get('description', ''),
        created_by=user_id
    )
    db.session.add(dashboard)
    db.session.commit()
    
    # Add creator as owner
    member = DashboardMember(
        dashboard_id=dashboard.id,
        user_id=user_id,
        role='owner'
    )
    db.session.add(member)
    db.session.commit()
    
    return jsonify({
        'message': 'Dashboard created successfully',
        'dashboard_id': dashboard.id
    })

@app.route('/api/dashboard/<int:dashboard_id>', methods=['DELETE'])
def delete_dashboard(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check if user is the owner of this dashboard
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id,
        role='owner'
    ).first()
    
    if not member:
        return jsonify({'error': 'Only dashboard owners can delete dashboards'}), 403
    
    try:
        # Get the dashboard
        dashboard = Dashboard.query.get(dashboard_id)
        if not dashboard:
            return jsonify({'error': 'Dashboard not found'}), 404
        
        # Delete all related data first (to maintain referential integrity)
        # Delete expenses
        Expense.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Delete uploaded files
        UploadedFile.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Delete chat sessions
        ChatSession.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Delete dashboard members
        DashboardMember.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Finally delete the dashboard
        db.session.delete(dashboard)
        db.session.commit()
        
        return jsonify({
            'message': 'Dashboard deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to delete dashboard: {str(e)}'}), 500

@app.route('/dashboard/<int:dashboard_id>')
def dashboard_view(dashboard_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    # Check if user has access to this dashboard
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    
    if not member:
        return "Access denied", 403
    
    dashboard = Dashboard.query.get(dashboard_id)
    current_year_month = datetime.now().strftime('%Y-%m')
    return render_template('dashboard_view.html', dashboard=dashboard, current_year_month=current_year_month)


# AI Processing Endpoints
@app.route('/api/dashboard/<int:dashboard_id>/ai/session', methods=['POST'])
def create_ai_session(dashboard_id):
    """Create a new AI session for CSV processing"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    csv_data = data.get('csv_data', '')
    
    # Generate session ID
    session_id = str(uuid.uuid4())
    
    # Store session in database
    chat_session = ChatSession(
        dashboard_id=dashboard_id,
        user_id=session['user_id'],
        session_id=session_id,
        original_csv_data=encrypt_str(csv_data),
        current_csv_data=encrypt_str(csv_data),
        conversation_history=encrypt_str('[]')
    )
    db.session.add(chat_session)
    db.session.commit()
    
    return jsonify({
        'session_id': session_id,
        'message': 'AI session created successfully'
    })

@app.route('/api/dashboard/<int:dashboard_id>/ai/session/<string:session_id>', methods=['GET'])
def get_ai_session(dashboard_id, session_id):
    """Get AI session data"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    chat_session = ChatSession.query.filter_by(
        session_id=session_id,
        dashboard_id=dashboard_id,
        user_id=session['user_id']
    ).first()
    
    if not chat_session:
        return jsonify({'error': 'Session not found'}), 404
    
    return jsonify({
        'session_id': chat_session.session_id,
        'csv_data': chat_session.get_csv_data(),
        'conversation_history': chat_session.get_conversation_history()
    })

@app.route('/api/dashboard/<int:dashboard_id>/ai/cleanup', methods=['POST'])
def cleanup_ai_data(dashboard_id):
    """Delete temporary AI artifacts (chat sessions, PDF extractions) to save space."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json() or {}
    session_id = data.get('session_id')
    extraction_id = data.get('extraction_id')
    
    deleted_sessions = 0
    deleted_extractions = 0
    
    try:
        if session_id:
            deleted_sessions = ChatSession.query.filter_by(
                session_id=session_id,
                dashboard_id=dashboard_id,
                user_id=session['user_id']
            ).delete()
        
        if extraction_id:
            deleted_extractions = PDFExtraction.query.filter_by(
                extraction_id=extraction_id,
                dashboard_id=dashboard_id,
                user_id=session['user_id']
            ).delete()
        
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to cleanup AI data: {exc}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'session_id': session_id,
            'extraction_id': extraction_id
        })
        return jsonify({'error': 'Failed to cleanup AI data'}), 500
    
    return jsonify({
        'message': 'Cleanup completed',
        'deleted_sessions': deleted_sessions,
        'deleted_extractions': deleted_extractions
    })

@app.route('/api/dashboard/<int:dashboard_id>/ai/process', methods=['POST'])
@limiter.limit(RATE_LIMITS['ai_processing'])
def process_csv_with_ai(dashboard_id):
    """Process CSV data with AI"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    session_id = data.get('session_id')
    prompt = data.get('prompt')
    csv_data = data.get('csv_data', '')
    
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    
    try:
        user = User.query.get(session['user_id'])
        
        # Get or create session
        chat_session = None
        if session_id:
            chat_session = ChatSession.query.filter_by(
                session_id=session_id,
                dashboard_id=dashboard_id,
                user_id=session['user_id']
            ).first()
        
        if not chat_session:
            # Create new session
            session_id = str(uuid.uuid4())
            chat_session = ChatSession(
                dashboard_id=dashboard_id,
                user_id=session['user_id'],
                session_id=session_id,
                original_csv_data=encrypt_str(csv_data),
                current_csv_data=encrypt_str(csv_data),
                conversation_history=encrypt_str('[]')
            )
            db.session.add(chat_session)
        
        # Get conversation history
        conversation_history = chat_session.get_conversation_history()
        
        # Add user message to conversation
        chat_session.add_message('user', prompt, csv_data)
        
        # Process with AI
        processed_csv, ai_response = call_aimodel_with_context_and_csv(
            user, 
            "",  # No PDF text for CSV processing
            "csv_data.csv", 
            prompt, 
            conversation_history,
            csv_data
        )
        
        # Update session with new CSV data and AI response
        chat_session.update_csv_data(processed_csv)
        chat_session.add_message('assistant', ai_response, processed_csv)
        db.session.commit()
        
        return jsonify({
            'processed_csv': processed_csv,
            'message': ai_response,
            'session_id': chat_session.session_id
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"CSV processing error: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id
        })
        return jsonify({'error': f'CSV processing failed: {str(e)}'}), 500

@app.route('/api/dashboard/<int:dashboard_id>/ai/extract-pdf', methods=['POST'])
@limiter.limit(RATE_LIMITS['pdf_upload'])
def extract_from_pdf(dashboard_id):
    """Extract text from PDF using Camelot or PyPDF and store in database"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    pdf_data = data.get('pdf_data')
    filename = data.get('filename', 'unknown.pdf')
    extraction_method = data.get('extraction_method', 'camelot')
    page_numbers = data.get('page_numbers', '')
    
    if not pdf_data:
        return jsonify({'error': 'PDF data is required'}), 400
    
    try:
        # Convert base64 PDF data back to bytes for validation
        import base64
        pdf_bytes = base64.b64decode(pdf_data)
        
        # Validate file upload security
        try:
            validate_file_upload(pdf_bytes, filename)
        except ValueError as e:
            logger.warning(f"File upload validation failed: {e}", extra={
                'user_id': session['user_id'],
                'dashboard_id': dashboard_id,
                'filename': filename
            })
            return jsonify({'error': str(e)}), 400
        
        logger.info(f"Extracting text from PDF: {filename}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'extraction_method': extraction_method,
            'page_numbers': page_numbers,
            'pdf_filename': filename
        })
        
        # Extract text from PDF using selected method
        extracted_text = extract_text_from_pdf_data(pdf_data, filename, extraction_method, page_numbers)
        
        if not extracted_text:
            logger.error(f"Failed to extract text from {filename}", extra={
                'user_id': session['user_id'],
                'dashboard_id': dashboard_id,
                'pdf_filename': filename
            })
            return jsonify({'error': 'PDF extraction failed - no text found'}), 500
        
        logger.info(f"PDF extraction successful: {len(extracted_text)} characters", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'pdf_filename': filename,
            'extracted_length': len(extracted_text)
        })
        
        # Generate unique extraction ID
        extraction_id = str(uuid.uuid4())
        
        # Delete any existing extraction for this dashboard/user
        PDFExtraction.query.filter_by(
            dashboard_id=dashboard_id,
            user_id=session['user_id']
        ).delete()
        
        # Store extracted text in database with empty CSV data
        pdf_extraction = PDFExtraction(
            dashboard_id=dashboard_id,
            user_id=session['user_id'],
            extraction_id=extraction_id,
            filename=filename,
            extracted_text=encrypt_str(extracted_text),
            current_csv_data=encrypt_str(''),  # Start with empty CSV
            conversation_history=encrypt_str('[]'),  # Start with empty conversation
            status='extracted'  # Changed from 'completed' to 'extracted'
        )
        db.session.add(pdf_extraction)
        db.session.commit()
        
        logger.info(f"PDF extraction stored in database with ID: {extraction_id}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'extraction_id': extraction_id
        })
        
        return jsonify({
            'extraction_id': extraction_id,
            'message': 'PDF extracted successfully',
            'status': 'extracted'
        })
        
    except Exception as e:
        logger.error(f"PDF extraction error: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'filename': filename
        })
        return jsonify({'error': f'PDF extraction failed: {str(e)}'}), 500


@app.route('/api/dashboard/<int:dashboard_id>/ai/extract-excel', methods=['POST'])
def extract_from_excel(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    excel_data = data.get('excel_data')
    filename = data.get('filename', 'unknown.xlsx')
    prompt = data.get('prompt', '')
    
    if not excel_data:
        return jsonify({'error': 'Excel data is required'}), 400
    
    try:
        user = User.query.get(session['user_id'])
        
        try:
            logger.info(f"Calling AI model API for Excel extraction: {filename}", extra={
                'user_id': session['user_id'],
                'dashboard_id': dashboard_id,
                'excel_filename': filename
            })
            # Call real AI model API for Excel extraction
            csv_data = call_aimodel_excel_api(user, excel_data, filename, prompt)
            logger.info(f"AI model API call successful, returned {len(csv_data)} characters", extra={
                'user_id': session['user_id'],
                'dashboard_id': dashboard_id,
                'excel_filename': filename,
                'csv_data_length': len(csv_data)
            })
        except ValueError as e:
            # Handle missing API key or unsupported model
            return jsonify({'error': str(e)}), 400
        except Exception as e:
            logger.error(f"AI model API error: {str(e)}", extra={
                'user_id': session['user_id'],
                'dashboard_id': dashboard_id,
                'excel_filename': filename
            })
            return jsonify({'error': f'Excel extraction failed: {str(e)}'}), 500
        
        return jsonify({
            'csv_data': csv_data,
            'message': 'Excel extracted successfully'
        })
        
    except Exception as e:
        logger.error(f"General Excel processing error: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id
        })
        return jsonify({'error': f'Excel processing failed: {str(e)}'}), 500

@app.route('/api/dashboard/<int:dashboard_id>/ai/process-chat', methods=['POST'])
@limiter.limit(RATE_LIMITS['ai_processing'])
def process_pdf_chat(dashboard_id):
    """Process PDF chat conversation with AI"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    extraction_id = data.get('extraction_id')
    prompt = data.get('prompt')
    
    if not extraction_id:
        return jsonify({'error': 'Extraction ID is required'}), 400
    if not prompt:
        return jsonify({'error': 'Prompt is required'}), 400
    
    try:
        user = User.query.get(session['user_id'])
        
        # Get the PDF extraction from database
        pdf_extraction = PDFExtraction.query.filter_by(
            extraction_id=extraction_id,
            dashboard_id=dashboard_id,
            user_id=session['user_id']
        ).first()
        
        if not pdf_extraction:
            return jsonify({'error': 'PDF extraction not found or access denied'}), 404
        
        # Get conversation history
        conversation_history = pdf_extraction.get_conversation_history()
        
        # Add user message to conversation
        pdf_extraction.add_message('user', prompt, pdf_extraction.get_current_csv_data())
        
        # Process with AI using the extracted text and current CSV data
        processed_csv, ai_response = call_aimodel_with_context_and_csv(
            user, 
            pdf_extraction.get_extracted_text(), 
            pdf_extraction.filename, 
            prompt, 
            conversation_history,
            pdf_extraction.get_current_csv_data()
        )
        
        # Update extraction with new CSV data and AI response
        pdf_extraction.update_csv_data(processed_csv)
        pdf_extraction.add_message('assistant', ai_response, processed_csv)
        db.session.commit()
        
        return jsonify({
            'csv_data': processed_csv,
            'message': ai_response,
            'extraction_id': extraction_id
        })
        
    except ValueError as e:
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"PDF chat processing error: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'extraction_id': extraction_id
        })
        return jsonify({'error': f'PDF chat processing failed: {str(e)}'}), 500


def extract_text_from_pdf_data(pdf_data, filename, extraction_method='camelot', page_numbers=''):
    """
    Extract text from PDF data using Camelot (for tables) or PyPDF (for text)
    """
    try:
        from io import BytesIO
        import tempfile
        import os
        import base64
        
        # Convert base64 PDF data back to bytes
        pdf_bytes = base64.b64decode(pdf_data)
        
        # Create a temporary file for PDF processing
        with tempfile.NamedTemporaryFile(delete=False, suffix='.pdf') as temp_file:
            temp_file.write(pdf_bytes)
            temp_file_path = temp_file.name
        
        try:
            text_content = ""
            
            # Parse page numbers if provided
            pages_to_extract = 'all'
            if page_numbers and page_numbers.strip():
                try:
                    # Parse comma-separated page numbers (e.g., "1,3,5")
                    page_list = [int(p.strip()) for p in page_numbers.split(',') if p.strip().isdigit()]
                    if page_list:
                        pages_to_extract = ','.join(map(str, page_list))
                        logger.debug(f"Extracting specific pages: {pages_to_extract}")
                except Exception as e:
                    logger.warning(f"Error parsing page numbers '{page_numbers}': {e}")
                    pages_to_extract = 'all'
            
            if extraction_method == 'camelot':
                # Use Camelot for table extraction
                text_content = extract_with_camelot(temp_file_path, filename, pages_to_extract)
            else:
                # Use PyPDF for text extraction
                text_content = extract_with_pypdf(temp_file_path, filename, pages_to_extract)
            
            logger.debug(f"Total extracted content: {len(text_content)} characters")
            return text_content.strip()
            
        finally:
            # Clean up temporary file
            os.unlink(temp_file_path)
        
    except Exception as e:
        logger.error(f"Error extracting text from PDF {filename} with {extraction_method}: {str(e)}")
        return None

def extract_with_camelot(temp_file_path, filename, pages='all'):
    """
    Extract tables from PDF using Camelot
    """
    try:
        import camelot
        
        logger.debug(f"Extracting tables from PDF using Camelot: {filename}, pages: {pages}")
        
        text_content = ""
        total_tables_found = 0
        
        # Try stream method first (better for bank statements without clear borders)
        try:
            tables = camelot.read_pdf(temp_file_path, flavor='stream', pages=pages)
            if tables:
                stream_tables = len(tables)
                logger.debug(f"Stream method found {stream_tables} tables")
                total_tables_found += stream_tables
                
                for table_num, table in enumerate(tables):
                    if table is not None and not table.df.empty:
                        text_content += f"--- Table {table_num + 1} (Stream) ---\n"
                        table_text = table.df.to_string(index=False)
                        text_content += table_text + "\n\n"
            else:
                logger.debug("No tables found with stream method")
        except Exception as e:
            logger.warning(f"Stream method failed: {e}")
        
        # If no tables found with stream, try lattice method
        if not text_content:            
            try:
                tables = camelot.read_pdf(temp_file_path, flavor='lattice', pages=pages)
                if tables:
                    lattice_tables = len(tables)
                    logger.debug(f"Lattice method found {lattice_tables} tables")
                    total_tables_found += lattice_tables
                    
                    for table_num, table in enumerate(tables):
                        if table is not None and not table.df.empty:
                            text_content += f"--- Table {table_num + 1} (Lattice) ---\n"
                            table_text = table.df.to_string(index=False)
                            text_content += table_text + "\n\n"
                else:
                    logger.debug("No tables found with lattice method")
            except Exception as e:
                logger.warning(f"Lattice method failed: {e}")
        
        logger.debug(f"Total tables found: {total_tables_found}")
        
        # If still no tables found, fallback to PyPDF
        if not text_content:
            logger.debug("No tables found with Camelot, falling back to PyPDF text extraction...")
            text_content = extract_with_pypdf(temp_file_path, filename, pages)
        
        return text_content
        
    except Exception as e:
        logger.error(f"Camelot extraction failed: {e}")
        # Fallback to PyPDF
        return extract_with_pypdf(temp_file_path, filename, pages)

def extract_with_pypdf(temp_file_path, filename, pages='all'):
    """
    Extract text from PDF using PyPDF
    """
    try:
        from PyPDF2 import PdfReader
        
        logger.debug(f"Extracting text from PDF using PyPDF: {filename}, pages: {pages}")
        
        text_content = ""
        pdf_reader = PdfReader(temp_file_path)
        total_pages = len(pdf_reader.pages)
        
        # Determine which pages to extract
        if pages == 'all':
            pages_to_extract = range(total_pages)
        else:
            # Parse comma-separated page numbers (1-indexed)
            page_list = [int(p.strip()) - 1 for p in pages.split(',') if p.strip().isdigit()]
            pages_to_extract = [p for p in page_list if 0 <= p < total_pages]
            if not pages_to_extract:
                pages_to_extract = range(total_pages)  # Fallback to all pages
        
        for page_num in pages_to_extract:
            if 0 <= page_num < total_pages:
                page = pdf_reader.pages[page_num]
                page_text = page.extract_text()
                if page_text.strip():
                    text_content += f"--- Page {page_num + 1} Text ---\n"
                    text_content += page_text + "\n\n"
                    logger.debug(f"Page {page_num + 1} text extracted ({len(page_text)} chars)")
        
        return text_content
        
    except Exception as e:
        logger.error(f"PyPDF text extraction failed: {e}")
        return ""

def extract_data_from_excel(excel_data, filename):
    """
    Extract data from Excel file using pandas
    """
    try:
        import pandas as pd
        from io import BytesIO
        import base64
        
        # Convert base64 Excel data back to bytes
        excel_bytes = base64.b64decode(excel_data)
        
        # Read Excel file
        excel_file = BytesIO(excel_bytes)
        
        # Try to read all sheets
        excel_data = pd.read_excel(excel_file, sheet_name=None)
        
        text_content = ""
        for sheet_name, df in excel_data.items():
            if df is not None and not df.empty:
                text_content += f"--- Sheet: {sheet_name} ---\n"
                
                # Convert DataFrame to string representation
                df_text = df.to_string(index=False)
                text_content += df_text + "\n\n"
        
        return text_content.strip()
        
    except Exception as e:
        logger.error(f"Error extracting data from Excel {filename}: {str(e)}")
        return None

def call_aimodel_excel_api(user, excel_data, filename, prompt=""):
    """Call AI model API to extract data from Excel - using data extraction first"""
    # Get user's selected AI model
    model_key = user.default_ai_provider or 'mistral'
    model_config = AI_MODELS.get(model_key)
    
    if not model_config:
        raise ValueError(f"Unsupported AI model: {model_key}")
    
    # Get API key for the selected model
    api_key = user.get_decrypted_api_key(model_config['api_key_field'])
    if not api_key:
        raise ValueError(f"{model_config['name']} API key not configured")
    
    url = model_config['api_url']
    model_name = model_config['model_name']
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Create system prompt for Excel processing
    system_prompt = """You are a financial document processing assistant. You extract transaction data from Excel spreadsheets and convert it to CSV format.
    
    Extract all transactions from the Excel data and return them in CSV format with these columns:
    - Date (format: YYYY-MM-DD)
    - Description (the merchant or transaction description)
    - Amount (numeric value, positive for expenses)
    - Category (use one of: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation)
    
    Only include actual transactions, not headers or totals. If you can't determine the category, use 'misc'.
    Return only the CSV data, no additional text.
    """
    
    # Extract data from Excel first
    logger.debug(f"Extracting data from Excel: {filename}")
    extracted_data = extract_data_from_excel(excel_data, filename)
    
    if not extracted_data:
        logger.warning(f"Failed to extract data from {filename}, using fallback")
        return handle_large_excel_fallback(filename, prompt)
    
    logger.debug(f"Data extraction successful: {len(extracted_data)} characters")
    logger.debug(f"Estimated tokens: {len(extracted_data) // 4}")
    
    # Check if data is too large and needs chunking
    if len(extracted_data) > 50000:  # Conservative limit for text
        logger.debug(f"Data too large ({len(extracted_data)} chars), using chunking approach")
        return process_large_excel_with_chunking(api_key, extracted_data, filename, prompt, system_prompt, url, headers)
    
    # Build user message with extracted data
    if prompt:
        user_message = f"Extract transaction data from this Excel file ({filename}). Here's the extracted data:\n\n{extracted_data}\n\nAdditional instructions: {prompt}"
    else:
        user_message = f"Extract transaction data from this Excel file ({filename}). Here's the extracted data:\n\n{extracted_data}"
    
    payload = {
        "model": "deepseek-chat",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": user_message
            }
        ],
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    logger.debug(f"Sending request to DeepSeek API with {len(extracted_data)} characters of extracted data")
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=30)
        logger.debug(f"DeepSeek API response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"DeepSeek API error response: {response.text}")
            response.raise_for_status()
        
        result = response.json()
        ai_response = result['choices'][0]['message']['content']
        logger.debug(f"DeepSeek API response received: {len(ai_response)} characters")
        
        # Extract CSV from response
        lines = ai_response.split('\n')
        csv_lines = []
        
        for line in lines:
            if ',' in line and (line.startswith('"') or any(char.isdigit() for char in line)):
                csv_lines.append(line.strip())
            elif line.strip().lower().startswith('date,description,amount,category'):
                csv_lines.append(line.strip())
        
        # If no CSV found, return a default structure
        if not csv_lines:
            logger.warning("No CSV found in AI response, using default structure")
            csv_lines = [
                "Date,Description,Amount,Category",
                "2025-10-01,Sample Transaction,100.00,misc"
            ]
        
        return '\n'.join(csv_lines)
        
    except requests.exceptions.RequestException as e:
        logger.error(f"DeepSeek API request failed: {str(e)}")
        # Fallback for API errors
        return handle_large_excel_fallback(filename, prompt)
    except Exception as e:
        logger.error(f"DeepSeek API processing failed: {str(e)}")
        # Fallback for other errors
        return handle_large_excel_fallback(filename, prompt)





def call_aimodel_with_context_and_csv(user, extracted_text, filename, prompt, conversation_history, current_csv_data):
    """Call AI model API with conversation context and current CSV data for processing"""
    # Get user's selected AI model
    model_key = user.default_ai_provider or 'deepseek'
    model_config = AI_MODELS.get(model_key)
    
    if not model_config:
        raise ValueError(f"Unsupported AI model: {model_key}")
    
    # Get API key for the selected model
    api_key = user.get_decrypted_api_key(model_config['api_key_field'])
    if not api_key:
        raise ValueError(f"{model_config['name']} API key not configured")
    
    url = model_config['api_url']
    model_name = model_config['model_name']
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Determine if this is initial extraction or follow-up processing
    is_initial_extraction = not current_csv_data or len(current_csv_data.strip()) == 0
    
    if is_initial_extraction:
        # System prompt for initial PDF extraction
        system_prompt = """You are a financial document processing assistant. You extract and process transaction data from bank statements and convert it to CSV format.
        
        Extract all transactions from the bank statement text and return them in CSV format with these columns:
        - Date (format: YYYY-MM-DD)
        - Description (the merchant or transaction description)
        - Amount (numeric value, positive for expenses)
        - Category (use one of: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation)
        
        Only include actual transactions, not headers or totals. If you can't determine the category, use 'misc'.
        Return only the CSV data, no additional text.
        """
        
        # Build messages with conversation history
        messages = [
            {
                "role": "system",
                "content": system_prompt
            }
        ]
        
        # Add conversation history (limit to last 4 turns to stay within token limits)
        for turn in conversation_history[-4:]:
            messages.append({
                "role": turn.get('role', 'user'),
                "content": turn.get('content', '')
            })
        
        # Add current user message with extracted text
        current_message = f"Extract transaction data from this bank statement ({filename}). Here's the extracted text:\n\n{extracted_text}\n\nAdditional instructions: {prompt}"
        messages.append({
            "role": "user",
            "content": current_message
        })
        
    else:
        # System prompt for CSV processing with conversation context
        system_prompt = """You are a CSV data processing assistant. You help users filter, categorize, and transform their expense data.
        
        The user will provide CSV data and a request. You should:
        1. Understand the user's request
        2. Process the CSV data accordingly
        3. Return the processed CSV data
        4. Provide a brief explanation of what you did
        
        Always return valid CSV format with these columns: Date, Description, Amount, Category.
        For categorization, use these categories: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurant, service, shopping, transport, utility, vacation.
        
        Example responses:
        - "I've filtered the data to show only transactions above $50. Here's the processed CSV:"
        - "I've categorized the expenses based on the descriptions. Here's the updated CSV:"
        """
        
        # Build messages with conversation history
        messages = [
            {
                "role": "system",
                "content": system_prompt
            }
        ]
        
        # Add conversation history (limit to last 4 turns to stay within token limits)
        for turn in conversation_history[-4:]:
            messages.append({
                "role": turn.get('role', 'user'),
                "content": turn.get('content', '')
            })
        
        # Add current user message with current CSV data
        current_message = f"CSV Data:\n{current_csv_data}\n\nUser Request: {prompt}\n\nPlease process this CSV data and return the processed CSV along with a brief explanation."
        messages.append({
            "role": "user",
            "content": current_message
        })
    
    payload = {
        "model": model_name,
        "messages": messages,
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    logger.debug(f"Sending request to {model_config['name']} API with {len(conversation_history)} conversation turns", extra={
        'is_initial_extraction': is_initial_extraction,
        'conversation_turns': len(conversation_history)
    })
    
    try:
        response = requests.post(url, headers=headers, json=payload, timeout=60)
        logger.debug(f"API response status: {response.status_code}")
        
        if response.status_code != 200:
            logger.error(f"API error response: {response.text}")
            response.raise_for_status()
        
        result = response.json()
        ai_response = result['choices'][0]['message']['content']
        logger.debug(f"API response received: {len(ai_response)} characters")
        
        # Extract CSV from response - improved logic to separate explanation from CSV
        lines = ai_response.split('\n')
        csv_lines = []
        explanation_lines = []
        in_csv_section = False
        
        for line in lines:
            line = line.strip()
            
            # Check if we've found the CSV header
            if line.lower().startswith('date,description,amount,category'):
                in_csv_section = True
                csv_lines.append(line)
                continue
            
            # If we're in CSV section and line looks like CSV data
            if in_csv_section and ',' in line:
                # Check if this line contains actual CSV data (has date-like patterns or amounts)
                has_date = any(pattern in line for pattern in ['202', '2024', '2025', '2026'])
                has_amount = any(char.isdigit() for char in line) and any(char in line for char in ['.', '$'])
                
                if has_date or has_amount:
                    csv_lines.append(line)
                else:
                    # This might be explanation text mixed in CSV section
                    explanation_lines.append(line)
            elif not in_csv_section:
                # This is explanation text before CSV section
                explanation_lines.append(line)
            else:
                # This might be explanation text after CSV section
                explanation_lines.append(line)
        
        # If no CSV found, try alternative CSV detection
        if not csv_lines:
            logger.debug("No CSV found with header detection, trying alternative detection")
            for line in lines:
                line = line.strip()
                # Look for lines that have CSV-like structure (comma-separated with dates/amounts)
                if ',' in line and len(line.split(',')) >= 3:
                    # Check if it has date-like patterns or amounts
                    has_date = any(pattern in line for pattern in ['202', '2024', '2025', '2026', '/', '-'])
                    has_amount = any(char.isdigit() for char in line) and any(char in line for char in ['.', '$'])
                    
                    if has_date or has_amount:
                        csv_lines.append(line)
                    else:
                        explanation_lines.append(line)
                else:
                    explanation_lines.append(line)
        
        # If still no CSV found, return a default structure
        if not csv_lines:
            logger.warning("No CSV found in AI response, using default structure")
            csv_lines = [
                "Date,Description,Amount,Category",
                "2025-10-01,Sample Transaction,100.00,misc"
            ]
        
        # Clean up CSV data - remove any explanation text that might have been included
        clean_csv_lines = []
        for line in csv_lines:
            # Skip lines that look like explanation text
            if any(keyword in line.lower() for keyword in ['explanation:', 'i removed', 'i filtered', 'i categorized', '**']):
                explanation_lines.append(line)
            else:
                clean_csv_lines.append(line)
        
        csv_data = '\n'.join(clean_csv_lines)
        
        # Create a clean explanation message
        explanation = '\n'.join(explanation_lines).strip()
        if not explanation:
            explanation = "I've processed your request. Here's the updated CSV data."
        
        return csv_data, explanation
        
    except requests.exceptions.RequestException as e:
        logger.error(f"API request failed: {str(e)}")
        # Fallback for API errors
        fallback_csv = "Date,Description,Amount,Category\n2025-10-01,API Error - Please try again,0.00,misc"
        return fallback_csv, "AI processing failed. Please try again."
    except Exception as e:
        logger.error(f"API processing failed: {str(e)}")
        # Fallback for other errors
        fallback_csv = "Date,Description,Amount,Category\n2025-10-01,Processing Error - Please try again,0.00,misc"
        return fallback_csv, "AI processing failed. Please try again."



# Dashboard Members Endpoint
@app.route('/api/dashboard/<int:dashboard_id>/members', methods=['GET'])
def get_dashboard_members(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    members = DashboardMember.query.filter_by(dashboard_id=dashboard_id).all()
    member_data = []
    
    for member in members:
        member_data.append({
            'user': {
                'id': member.user.id,
                'name': member.user.name,
                'email': member.user.email
            },
            'role': member.role
        })
    
    return jsonify(member_data)

# Dashboard Invitation Endpoints
@app.route('/api/dashboard/<int:dashboard_id>/invite', methods=['POST'])
def invite_to_dashboard(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check if user is owner of this dashboard
    owner_member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id,
        role='owner'
    ).first()
    
    if not owner_member:
        return jsonify({'error': 'Only dashboard owners can invite users'}), 403
    
    data = request.get_json()
    invited_email = data.get('email')
    message = data.get('message', '')
    
    if not invited_email:
        return jsonify({'error': 'Email is required'}), 400
    
    # Find user by email
    invited_user = User.query.filter_by(email=invited_email).first()
    if not invited_user:
        return jsonify({'error': 'User with this email not found'}), 404
    
    # Check if user is already a member
    existing_member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=invited_user.id
    ).first()
    
    if existing_member:
        return jsonify({'error': 'User is already a member of this dashboard'}), 400
    
    # Check if there's already a pending invitation
    existing_invitation = DashboardInvitation.query.filter_by(
        dashboard_id=dashboard_id,
        invited_user_id=invited_user.id,
        status='pending'
    ).first()
    
    if existing_invitation:
        return jsonify({'error': 'User already has a pending invitation'}), 400
    
    # Create invitation
    invitation = DashboardInvitation(
        dashboard_id=dashboard_id,
        invited_user_id=invited_user.id,
        invited_by_user_id=user_id,
        message=message
    )
    
    db.session.add(invitation)
    db.session.commit()
    
    return jsonify({
        'message': 'Invitation sent successfully',
        'invitation_id': invitation.id
    })

@app.route('/api/dashboard/invitations', methods=['GET'])
def get_user_invitations():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Get pending invitations for the current user
    invitations = DashboardInvitation.query.filter_by(
        invited_user_id=user_id,
        status='pending'
    ).all()
    
    invitation_data = []
    for invitation in invitations:
        invitation_data.append({
            'id': invitation.id,
            'dashboard': {
                'id': invitation.dashboard.id,
                'name': invitation.dashboard.name,
                'description': invitation.dashboard.description
            },
            'invited_by': {
                'id': invitation.invited_by_user.id,
                'name': invitation.invited_by_user.name,
                'email': invitation.invited_by_user.email
            },
            'message': invitation.message,
            'created_at': invitation.created_at.isoformat()
        })
    
    return jsonify(invitation_data)

@app.route('/api/dashboard/invitations/<int:invitation_id>/respond', methods=['POST'])
def respond_to_invitation(invitation_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Get invitation
    invitation = DashboardInvitation.query.filter_by(
        id=invitation_id,
        invited_user_id=user_id,
        status='pending'
    ).first()
    
    if not invitation:
        return jsonify({'error': 'Invitation not found or already processed'}), 404
    
    data = request.get_json()
    action = data.get('action')  # 'accept' or 'reject'
    
    if action not in ['accept', 'reject']:
        return jsonify({'error': 'Invalid action. Use "accept" or "reject"'}), 400
    
    if action == 'accept':
        # Add user as member
        member = DashboardMember(
            dashboard_id=invitation.dashboard_id,
            user_id=user_id,
            role='member'
        )
        db.session.add(member)
        
        # Create default user settings
        settings = UserDashboardSettings(
            user_id=user_id,
            dashboard_id=invitation.dashboard_id,
            edit_mode='private'  # Default to private mode
        )
        db.session.add(settings)
        
        invitation.status = 'accepted'
        
        message = 'Invitation accepted successfully'
    else:
        invitation.status = 'rejected'
        message = 'Invitation rejected'
    
    db.session.commit()
    
    return jsonify({'message': message})

# User Dashboard Settings Endpoints
@app.route('/api/dashboard/<int:dashboard_id>/settings', methods=['GET'])
def get_dashboard_settings(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get or create settings
    settings = UserDashboardSettings.query.filter_by(
        user_id=user_id,
        dashboard_id=dashboard_id
    ).first()
    
    if not settings:
        # Create default settings
        settings = UserDashboardSettings(
            user_id=user_id,
            dashboard_id=dashboard_id,
            edit_mode='private'
        )
        db.session.add(settings)
        db.session.commit()
    
    return jsonify({
        'edit_mode': settings.edit_mode
    })

@app.route('/api/dashboard/<int:dashboard_id>/settings', methods=['PUT'])
def update_dashboard_settings(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    edit_mode = data.get('edit_mode')
    
    if edit_mode not in ['private', 'public']:
        return jsonify({'error': 'Invalid edit mode. Use "private" or "public"'}), 400
    
    # Get or create settings
    settings = UserDashboardSettings.query.filter_by(
        user_id=user_id,
        dashboard_id=dashboard_id
    ).first()
    
    if not settings:
        settings = UserDashboardSettings(
            user_id=user_id,
            dashboard_id=dashboard_id,
            edit_mode=edit_mode
        )
        db.session.add(settings)
    else:
        settings.edit_mode = edit_mode
    
    db.session.commit()
    
    return jsonify({
        'message': 'Settings updated successfully',
        'edit_mode': settings.edit_mode
    })

# Expense Management Endpoints
@app.route('/api/dashboard/<int:dashboard_id>/expenses', methods=['GET'])
def get_expenses(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    expenses = Expense.query.filter_by(dashboard_id=dashboard_id).all()
    expense_data = []
    
    for expense in expenses:
        expense_data.append({
            'id': expense.id,
            'date': expense.date.isoformat(),
            'description': expense.description,
            'amount': expense.amount,
            'category': expense.category,
            'user_name': expense.user.name,
            'user_id': expense.user_id
        })
    
    return jsonify(expense_data)


# Month-filtered expenses endpoint
@app.route('/api/dashboard/<int:dashboard_id>/expenses/month/<string:month>', methods=['GET'])
def get_expenses_by_month(dashboard_id, month):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    # Validate month format (YYYY-MM)
    import re
    if not re.match(r'^\d{4}-\d{2}$', month):
        return jsonify({'error': 'Invalid month format. Use YYYY-MM'}), 400
    
    expenses = Expense.query.filter_by(dashboard_id=dashboard_id).filter(
        db.func.strftime('%Y-%m', Expense.date) == month
    ).all()
    
    expense_data = []
    for expense in expenses:
        expense_data.append({
            'id': expense.id,
            'date': expense.date.isoformat(),
            'description': expense.description,
            'amount': expense.amount,
            'category': expense.category,
            'user_name': expense.user.name
        })
    
    return jsonify(expense_data)

@app.route('/api/dashboard/<int:dashboard_id>/expenses', methods=['POST'])
def create_expense(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json()
    
    try:
        # Validate expense data using security validation function
        validated_data = validate_expense_data(data)
        
        expense = Expense(
            dashboard_id=dashboard_id,
            user_id=session['user_id'],
            date=datetime.strptime(validated_data['date'], '%Y-%m-%d').date(),
            description=validated_data['description'],
            amount=float(validated_data['amount']),
            category=validated_data.get('category', 'misc')
        )
        db.session.add(expense)
        db.session.commit()
        
        # Log the expense creation
        logger.info(f"Expense created: {expense.description} - ${expense.amount}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'expense_id': expense.id
        })
        
        return jsonify({
            'message': 'Expense created successfully',
            'expense_id': expense.id
        })
        
    except ValueError as e:
        logger.warning(f"Expense validation failed: {e}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id
        })
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        logger.error(f"Failed to create expense: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id
        })
        return jsonify({'error': f'Failed to create expense: {str(e)}'}), 400

@app.route('/api/dashboard/<int:dashboard_id>/expenses/<int:expense_id>', methods=['PUT'])
def update_expense(dashboard_id, expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    # Check if expense exists and belongs to this dashboard
    expense = Expense.query.filter_by(
        id=expense_id,
        dashboard_id=dashboard_id
    ).first()
    
    if not expense:
        return jsonify({'error': 'Expense not found'}), 404
    
    # Check edit permissions - we need to check the edit mode of the expense owner
    expense_owner_settings = UserDashboardSettings.query.filter_by(
        user_id=expense.user_id,
        dashboard_id=dashboard_id
    ).first()
    
    # If no settings exist for the expense owner, create default private mode
    if not expense_owner_settings:
        expense_owner_settings = UserDashboardSettings(
            user_id=expense.user_id,
            dashboard_id=dashboard_id,
            edit_mode='private'
        )
        db.session.add(expense_owner_settings)
        db.session.commit()
    
    # Check if user can edit this expense
    # If expense owner has private mode, only they can edit their own expenses
    if expense_owner_settings.edit_mode == 'private' and expense.user_id != user_id:
        return jsonify({'error': 'This user has private mode enabled. You can only edit your own expenses.'}), 403
    
    data = request.get_json()
    
    try:
        # Validate expense data using security validation function
        validated_data = validate_expense_data(data)
        
        # Update fields if provided
        if 'date' in validated_data:
            expense.date = datetime.strptime(validated_data['date'], '%Y-%m-%d').date()
        if 'description' in validated_data:
            expense.description = validated_data['description']
        if 'amount' in validated_data:
            expense.amount = float(validated_data['amount'])
        if 'category' in validated_data:
            expense.category = validated_data['category']
        
        expense.updated_at = datetime.utcnow()
        db.session.commit()
        
        # Log the expense update
        logger.info(f"Expense updated: {expense.description} - ${expense.amount}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'expense_id': expense.id
        })
        
        return jsonify({
            'message': 'Expense updated successfully',
            'expense': {
                'id': expense.id,
                'date': expense.date.isoformat(),
                'description': expense.description,
                'amount': expense.amount,
                'category': expense.category
            }
        })
        
    except ValueError as e:
        logger.warning(f"Expense validation failed: {e}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'expense_id': expense_id
        })
        return jsonify({'error': str(e)}), 400
    except Exception as e:
        db.session.rollback()
        logger.error(f"Failed to update expense: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'expense_id': expense_id
        })
        return jsonify({'error': f'Failed to update expense: {str(e)}'}), 400

@app.route('/api/dashboard/<int:dashboard_id>/expenses/<int:expense_id>', methods=['DELETE'])
def delete_expense(dashboard_id, expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    user_id = session['user_id']
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=user_id
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    try:
        # Use a fresh query to get the expense in the current session
        expense = db.session.query(Expense).filter_by(
            id=expense_id,
            dashboard_id=dashboard_id
        ).first()
        
        if not expense:
            return jsonify({'error': 'Expense not found'}), 404
        
        # Check edit permissions - we need to check the edit mode of the expense owner
        expense_owner_settings = UserDashboardSettings.query.filter_by(
            user_id=expense.user_id,
            dashboard_id=dashboard_id
        ).first()
        
        # If no settings exist for the expense owner, create default private mode
        if not expense_owner_settings:
            expense_owner_settings = UserDashboardSettings(
                user_id=expense.user_id,
                dashboard_id=dashboard_id,
                edit_mode='private'
            )
            db.session.add(expense_owner_settings)
            db.session.commit()
        
        # Check if user can delete this expense
        # If expense owner has private mode, only they can delete their own expenses
        if expense_owner_settings.edit_mode == 'private' and expense.user_id != user_id:
            return jsonify({'error': 'This user has private mode enabled. You can only delete your own expenses.'}), 403
        
        # Delete the expense
        db.session.delete(expense)
        db.session.commit()
        
        return jsonify({
            'message': 'Expense deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Error deleting expense {expense_id}: {str(e)}", extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'expense_id': expense_id
        })
        return jsonify({'error': f'Failed to delete expense: {str(e)}'}), 400

# CSV Export Endpoint with Formula Injection Protection
@app.route('/api/dashboard/<int:dashboard_id>/export/csv', methods=['GET'])
def export_expenses_csv(dashboard_id):
    """Export expenses as CSV with formula injection protection"""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get expenses
    expenses = Expense.query.filter_by(dashboard_id=dashboard_id).all()
    
    # Build CSV data
    csv_lines = ['Date,Description,Amount,Category,User']
    
    for expense in expenses:
        csv_lines.append(
            f"{expense.date.isoformat()},{expense.description},{expense.amount},{expense.category},{expense.user.name}"
        )
    
    csv_data = '\n'.join(csv_lines)
    
    # Sanitize CSV data to prevent formula injection
    sanitized_csv = sanitize_csv_for_export(csv_data)
    
    # Log the export
    logger.info(f"CSV export generated for dashboard {dashboard_id}", extra={
        'user_id': session['user_id'],
        'dashboard_id': dashboard_id,
        'expense_count': len(expenses)
    })
    
    return jsonify({
        'csv_data': sanitized_csv,
        'filename': f'expenses_dashboard_{dashboard_id}_{datetime.now().strftime("%Y%m%d")}.csv'
    })

# Pivot Table Endpoint
@app.route('/api/dashboard/<int:dashboard_id>/pivot', methods=['GET'])
def get_pivot_data(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    # Get expenses and create pivot data
    expenses = Expense.query.filter_by(dashboard_id=dashboard_id).all()
    
    # Monthly pivot
    monthly_data = {}
    for expense in expenses:
        month_key = expense.date.strftime('%Y-%m')
        if month_key not in monthly_data:
            monthly_data[month_key] = {}
        
        if expense.category not in monthly_data[month_key]:
            monthly_data[month_key][expense.category] = 0
        
        monthly_data[month_key][expense.category] += expense.amount
    
    # Yearly pivot
    yearly_data = {}
    for expense in expenses:
        year_key = expense.date.strftime('%Y')
        if year_key not in yearly_data:
            yearly_data[year_key] = {}
        
        if expense.category not in yearly_data[year_key]:
            yearly_data[year_key][expense.category] = 0
        
        yearly_data[year_key][expense.category] += expense.amount
    
    return jsonify({
        'monthly': monthly_data,
        'yearly': yearly_data
    })

if __name__ == '__main__':
    import sys
    port = 5000
    if len(sys.argv) > 1 and sys.argv[1] == '--port':
        port = int(sys.argv[2])
    app.run(debug=True, host='0.0.0.0', port=port)
