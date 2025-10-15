from flask import Flask, render_template, redirect, url_for, session, request, jsonify, flash
from extensions import db
from authlib.integrations.flask_client import OAuth
import os
from datetime import datetime
import json
import requests
import uuid

# Initialize Flask app
app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-in-production")

# Environment configuration
AI_MOCK_MODE = os.environ.get("AI_MOCK_MODE", "true").lower() == "true"

# Database configuration
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///expenses.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db.init_app(app)
oauth = OAuth(app)

# OAuth configuration
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid_configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

# Import models
from models import User, Dashboard, DashboardMember, Expense, Category, UploadedFile, ChatSession

# Initialize database tables
def init_db():
    with app.app_context():
        db.create_all()
        print("Database tables created successfully")

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
                'picture': user.profile_picture
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
    user_info = token.get('userinfo')
    
    if user_info:
        # Store user in session
        session['user'] = {
            'id': user_info['sub'],
            'email': user_info['email'],
            'name': user_info['name'],
            'picture': user_info['picture']
        }
        
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
    
    return render_template('dashboard_list.html', dashboards=dashboards)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    return render_template('settings.html', user=user)

@app.route('/api/settings/update-api-key', methods=['POST'])
def update_api_key():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    data = request.get_json()
    user = User.query.get(session['user_id'])
    
    if 'mistral_api_key' in data:
        user.mistral_api_key = data['mistral_api_key']
        db.session.commit()
    
    return jsonify({'message': 'API key updated successfully'})

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
    if not data.get('csv_data'):
        return jsonify({'error': 'CSV data is required'}), 400
    
    # Create new chat session
    session_id = str(uuid.uuid4())
    chat_session = ChatSession(
        dashboard_id=dashboard_id,
        user_id=session['user_id'],
        session_id=session_id,
        original_csv_data=data['csv_data'],
        current_csv_data=data['csv_data']
    )
    db.session.add(chat_session)
    db.session.commit()
    
    return jsonify({
        'session_id': session_id,
        'message': 'AI session created successfully'
    })

@app.route('/api/dashboard/<int:dashboard_id>/ai/process', methods=['POST'])
def process_with_ai(dashboard_id):
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
    csv_data = data.get('csv_data')
    
    if not all([session_id, prompt, csv_data]):
        return jsonify({'error': 'Session ID, prompt, and CSV data are required'}), 400
    
    # Get chat session
    chat_session = ChatSession.query.filter_by(
        session_id=session_id,
        dashboard_id=dashboard_id,
        user_id=session['user_id']
    ).first()
    
    if not chat_session:
        return jsonify({'error': 'Session not found'}), 404
    
    # Check if we're in mock mode or if user has API key
    user = User.query.get(session['user_id'])
    
    if AI_MOCK_MODE:
        # Use mock AI response for local testing
        processed_csv, ai_response = mock_ai_response(prompt, csv_data)
    else:
        if not user or not user.mistral_api_key:
            return jsonify({'error': 'Mistral API key not configured'}), 400
        
        try:
            # Call real Mistral AI API
            processed_csv, ai_response = call_mistral_api(user.mistral_api_key, prompt, csv_data)
        except Exception as e:
            return jsonify({'error': f'AI processing failed: {str(e)}'}), 500
    
    # Update chat session
    chat_session.current_csv_data = processed_csv
    chat_session.add_message('user', prompt)
    chat_session.add_message('assistant', ai_response)
    db.session.commit()
    
    return jsonify({
        'message': ai_response,
        'processed_csv': processed_csv
    })

def mock_ai_response(prompt, csv_data):
    """Mock AI response for local testing - returns the CSV unchanged"""
    ai_response = f"I've processed your request: '{prompt}'. For local testing, I'm returning your original CSV data unchanged. In production, this would be processed by Mistral AI."
    
    # Return the original CSV data unchanged
    processed_csv = csv_data
    
    return processed_csv, ai_response

def call_mistral_api(api_key, prompt, csv_data):
    """Call Mistral AI API to process CSV data"""
    url = "https://api.mistral.ai/v1/chat/completions"
    
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }
    
    # Create system prompt for CSV processing
    system_prompt = """You are a CSV data processing assistant. You help users filter, categorize, and transform their expense data.
    
    The user will provide CSV data and a request. You should:
    1. Understand the user's request
    2. Process the CSV data accordingly
    3. Return the processed CSV data
    4. Provide a brief explanation of what you did
    
    Always return valid CSV format. Keep the same column structure unless explicitly requested to change it.
    For categorization, use these categories: car, gas, grocery, home exp, home setup, gym, hospital, misc, rent, mortgage, restaurants, service, shopping, transport, utilities, vacation.
    
    Example responses:
    - "I've filtered the data to show only transactions above $50. Here's the processed CSV:"
    - "I've categorized the expenses based on the descriptions. Here's the updated CSV:"
    """
    
    payload = {
        "model": "mistral-large-latest",
        "messages": [
            {
                "role": "system",
                "content": system_prompt
            },
            {
                "role": "user",
                "content": f"CSV Data:\n{csv_data}\n\nUser Request: {prompt}\n\nPlease process this CSV data and return the processed CSV along with a brief explanation."
            }
        ],
        "temperature": 0.1,
        "max_tokens": 2000
    }
    
    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    
    result = response.json()
    ai_response = result['choices'][0]['message']['content']
    
    # Extract CSV from response (simple parsing)
    lines = ai_response.split('\n')
    csv_lines = []
    in_csv_block = False
    
    for line in lines:
        if ',' in line and (line.startswith('"') or any(char.isdigit() for char in line)):
            csv_lines.append(line.strip())
        elif line.strip().lower().startswith('date,description,amount,category'):
            csv_lines.append(line.strip())
    
    processed_csv = '\n'.join(csv_lines) if csv_lines else csv_data
    
    return processed_csv, ai_response

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
            'user_name': expense.user.name
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
        expense = Expense(
            dashboard_id=dashboard_id,
            user_id=session['user_id'],
            date=datetime.strptime(data['date'], '%Y-%m-%d').date(),
            description=data['description'],
            amount=float(data['amount']),
            category=data.get('category', 'misc')
        )
        db.session.add(expense)
        db.session.commit()

        
        return jsonify({
            'message': 'Expense created successfully',
            'expense_id': expense.id
        })
        
    except Exception as e:
        return jsonify({'error': f'Failed to create expense: {str(e)}'}), 400

@app.route('/api/dashboard/<int:dashboard_id>/expenses/<int:expense_id>', methods=['PUT'])
def update_expense(dashboard_id, expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
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
    
    data = request.get_json()
    
    try:
        # Update fields if provided
        if 'date' in data:
            expense.date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        if 'description' in data:
            expense.description = data['description']
        if 'amount' in data:
            expense.amount = float(data['amount'])
        if 'category' in data:
            expense.category = data['category']
        
        expense.updated_at = datetime.utcnow()
        db.session.commit()
        
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
        
    except Exception as e:
        db.session.rollback()
        return jsonify({'error': f'Failed to update expense: {str(e)}'}), 400

@app.route('/api/dashboard/<int:dashboard_id>/expenses/<int:expense_id>', methods=['DELETE'])
def delete_expense(dashboard_id, expense_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    # Check dashboard access
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id, 
        user_id=session['user_id']
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
        
        # Delete the expense
        db.session.delete(expense)
        db.session.commit()
        
        return jsonify({
            'message': 'Expense deleted successfully'
        })
        
    except Exception as e:
        db.session.rollback()
        print(f"Error deleting expense {expense_id}: {str(e)}")
        return jsonify({'error': f'Failed to delete expense: {str(e)}'}), 400

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
