from extensions import db
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import json

from security_utils import decrypt_str, encrypt_str

# Predefined expense categories
EXPENSE_CATEGORIES = [
    'car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 
    'hospital', 'misc', 'rent', 'mortgage', 'restaurant', 
    'service', 'shopping', 'transport', 'utility', 'vacation'
]

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(255), unique=True, nullable=True)
    email = db.Column(db.String(255), unique=True, nullable=False)
    username = db.Column(db.String(255), unique=True, nullable=True)
    name = db.Column(db.String(255), nullable=False)
    profile_picture = db.Column(db.String(500))
    password_hash = db.Column(db.String(255))
    mistral_api_key = db.Column(db.String(255))
    openai_api_key = db.Column(db.String(255))
    anthropic_api_key = db.Column(db.String(255))
    deepseek_api_key = db.Column(db.String(255))
    default_ai_provider = db.Column(db.String(50), default='mistral')  # 'mistral', 'openai', 'anthropic', 'deepseek'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dashboards = db.relationship('DashboardMember', back_populates='user')
    expenses = db.relationship('Expense', back_populates='user')
    
    def set_password(self, password):
        """Set password hash"""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password hash"""
        return check_password_hash(self.password_hash, password)

    def set_encrypted_api_key(self, field_name, value):
        """Store API keys encrypted when possible."""
        if hasattr(self, field_name):
            setattr(self, field_name, encrypt_str(value))

    def get_decrypted_api_key(self, field_name):
        """Fetch decrypted API key value for the configured provider."""
        if not hasattr(self, field_name):
            return None
        return decrypt_str(getattr(self, field_name))
    
    def get_profile_picture(self):
        """Get profile picture URL, generate default if not set"""
        if self.profile_picture:
            return self.profile_picture
        # Generate default avatar using DiceBear API
        seed = self.username or self.email.split('@')[0] or str(self.id)
        return f'https://api.dicebear.com/7.x/avataaars/svg?seed={seed}&backgroundColor=b6e3f4,c0aede,d1d4f9'

class Dashboard(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    members = db.relationship('DashboardMember', back_populates='dashboard')
    expenses = db.relationship('Expense', back_populates='dashboard')

class DashboardMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    role = db.Column(db.String(50), default='member')  # 'owner', 'member'
    joined_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard', back_populates='members')
    user = db.relationship('User', back_populates='dashboards')

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    date = db.Column(db.Date, nullable=False)
    description = db.Column(db.String(500), nullable=False)
    amount = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(100), nullable=False)
    tags = db.Column(db.Text)  # JSON string for additional tags
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard', back_populates='expenses')
    user = db.relationship('User', back_populates='expenses')

class Category(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.Text)
    color = db.Column(db.String(7))  # Hex color code
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class UploadedFile(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    file_type = db.Column(db.String(50))  # 'csv', 'processed_csv'
    file_size = db.Column(db.Integer)
    storage_path = db.Column(db.String(500))  # Path in Google Cloud Storage
    processed_data = db.Column(db.Text)  # JSON string of processed data
    status = db.Column(db.String(50), default='uploaded')  # 'uploaded', 'processing', 'completed', 'error'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard')
    user = db.relationship('User')

class ChatSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    original_csv_data = db.Column(db.Text)  # Original CSV content
    current_csv_data = db.Column(db.Text)  # Current processed CSV content
    conversation_history = db.Column(db.Text)  # JSON string of chat messages
    status = db.Column(db.String(50), default='active')  # 'active', 'completed', 'archived'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard')
    user = db.relationship('User')
    
    def get_conversation_history(self):
        """Get conversation history as Python list"""
        if self.conversation_history:
            raw_history = decrypt_str(self.conversation_history)
            if raw_history:
                return json.loads(raw_history)
        return []
    
    def add_message(self, role, content, csv_data=None):
        """Add a message to conversation history"""
        history = self.get_conversation_history()
        
        # Add new message
        message = {
            'role': role,
            'content': content,
            'timestamp': datetime.utcnow().isoformat()
        }
        if csv_data:
            message['csv_data'] = csv_data
        
        history.append(message)
        self.conversation_history = encrypt_str(json.dumps(history))
    
    def get_csv_data(self):
        """Get current CSV data"""
        current = decrypt_str(self.current_csv_data) if self.current_csv_data else None
        original = decrypt_str(self.original_csv_data) if self.original_csv_data else None
        return current or original
    
    def update_csv_data(self, csv_data):
        """Update current CSV data"""
        self.current_csv_data = encrypt_str(csv_data)
        self.updated_at = datetime.utcnow()

class DashboardInvitation(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    invited_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    invited_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(50), default='pending')  # 'pending', 'accepted', 'rejected'
    message = db.Column(db.Text)  # Optional invitation message
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard')
    invited_user = db.relationship('User', foreign_keys=[invited_user_id])
    invited_by_user = db.relationship('User', foreign_keys=[invited_by_user_id])

class UserDashboardSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    edit_mode = db.Column(db.String(50), default='private')  # 'private', 'public'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    user = db.relationship('User')
    dashboard = db.relationship('Dashboard')
    
    # Unique constraint - one setting per user per dashboard
    __table_args__ = (db.UniqueConstraint('user_id', 'dashboard_id', name='unique_user_dashboard_settings'),)

class PDFExtraction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    extraction_id = db.Column(db.String(255), unique=True, nullable=False)  # UUID for frontend reference
    filename = db.Column(db.String(255), nullable=False)
    extracted_text = db.Column(db.Text)  # Large text content from PDF
    current_csv_data = db.Column(db.Text)  # Latest CSV data from AI processing
    conversation_history = db.Column(db.Text)  # JSON string of conversation history (last 5 turns)
    status = db.Column(db.String(50), default='processing')  # 'processing', 'completed', 'failed'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    
    # Relationships
    dashboard = db.relationship('Dashboard')
    user = db.relationship('User')
    
    # Index for faster lookups
    __table_args__ = (db.Index('idx_extraction_id', 'extraction_id'),)
    
    def get_conversation_history(self):
        """Get conversation history as Python list"""
        if self.conversation_history:
            raw_history = decrypt_str(self.conversation_history)
            if raw_history:
                return json.loads(raw_history)
        return []
    
    def add_message(self, role, content, csv_data=None):
        """Add a message to conversation history (limit to 5 turns)"""
        history = self.get_conversation_history()
        
        # Add new message
        message = {
            'role': role,
            'content': content,
            'timestamp': datetime.utcnow().isoformat()
        }
        if csv_data:
            message['csv_data'] = csv_data
        
        history.append(message)
        
        # Keep only last 5 turns
        if len(history) > 5:
            history = history[-5:]
        
        self.conversation_history = encrypt_str(json.dumps(history))
    
    def update_csv_data(self, csv_data):
        """Update current CSV data"""
        self.current_csv_data = encrypt_str(csv_data)
        self.updated_at = datetime.utcnow()

    def get_current_csv_data(self):
        """Return decrypted current CSV data"""
        return decrypt_str(self.current_csv_data)

    def get_extracted_text(self):
        """Return decrypted extracted text"""
        return decrypt_str(self.extracted_text)
