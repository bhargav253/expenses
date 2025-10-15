# Expense Tracker Web App

A comprehensive expense tracking web application with AI-powered data processing, built with Python Flask and modern web technologies.

## Features

### 🔐 Secure Authentication
- Google OAuth integration
- No password management required
- Secure session handling

### 📊 Dashboard Management
- Create and share expense tracking dashboards
- Role-based permissions (owner/member)
- Real-time collaboration

### 🔒 Client-Side PDF Processing
- Bank statements processed entirely in browser
- No sensitive PDF files uploaded to server
- Secure data extraction to CSV format

### 🤖 AI-Powered Data Processing
- Mistral AI integration for intelligent data filtering
- Natural language chat interface
- Context-aware conversations
- CSV transformation and categorization

### 📈 Interactive Expense Management
- **Monthly View**: Google Sheets-like editing with Handsontable.js
- **Yearly View**: Read-only summaries with DataTables.js
- **Category System**: Predefined expense categories
- **Pivot Tables**: Automatic expense analysis by month and category

### 🛡️ Security & Privacy
- Client-side PDF processing (bank statements never leave device)
- Encrypted API key storage
- Rate limiting for AI API calls
- Secure OAuth implementation

## Technology Stack

### Backend
- **Python Flask** - Web framework
- **SQLite** - Database (easily upgradable to PostgreSQL)
- **Authlib** - OAuth authentication
- **Requests** - HTTP client for AI API

### Frontend
- **Bootstrap 5** - Responsive UI framework
- **Handsontable.js** - Interactive spreadsheet editing
- **DataTables.js** - Advanced table functionality
- **PDF.js** - Client-side PDF processing
- **Vanilla JavaScript** - Custom functionality

### AI Integration
- **Mistral AI** - Primary AI provider
- Custom prompt engineering for CSV processing
- Context-aware conversation management

## Installation & Setup

### Prerequisites
- Python 3.8+
- Google OAuth credentials
- Mistral AI API key

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd expenses-app
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Set up the database (optional - runs automatically)**
   ```bash
   python setup_local.py
   ```

4. **Run the application**
   ```bash
   python app.py
   ```
   
   Or on a specific port:
   ```bash
   python app.py --port 5001
   ```

5. **Access the application**
   Open http://localhost:5000 (or your chosen port) in your browser

6. **Create your account**
   - Click "Sign Up" on the homepage
   - Fill in the registration form
   - No external dependencies needed for local testing

**Note for Local Testing:**
- SQLite database is used automatically
- No Google OAuth setup required
- AI functionality uses mock responses (no API key needed)
- All PDF processing happens client-side

### Cloud Deployment (Render.com)

1. **Fork this repository**

2. **Create a new Web Service on Render**
   - Connect your GitHub repository
   - Use the following settings:
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `gunicorn app:app`

3. **Configure environment variables**
   - `SECRET_KEY`: Generate a secure random key
   - `GOOGLE_CLIENT_ID`: Your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET`: Your Google OAuth client secret

4. **Deploy**
   - Render will automatically deploy your application

## Configuration

### Google OAuth Setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing one
3. Enable the Google+ API
4. Create OAuth 2.0 credentials
5. Add authorized redirect URIs:
   - `http://localhost:5000/auth/callback` (development)
   - `https://your-app.onrender.com/auth/callback` (production)

### Mistral AI Setup

1. Sign up at [Mistral AI](https://mistral.ai/)
2. Get your API key from the dashboard
3. Configure the API key in the app settings after login

## Usage Guide

### 1. Authentication
- Click "Login with Google" to authenticate
- First-time users are automatically registered

### 2. Dashboard Setup
- Create a new dashboard from the dashboard list
- Add a name and optional description
- Share dashboards with other users via email

### 3. Data Ingestion
- Navigate to the "Data Ingress" tab
- Upload bank statement PDFs (processed client-side)
- Review extracted CSV data
- Use AI chat to filter and categorize expenses
- Accept final CSV for storage

### 4. Expense Management
- **Monthly Tab**: Edit expenses directly like Google Sheets
- **Yearly Tab**: View summarized data with filtering
- **Categories**: Use predefined categories for organization
- **Pivot Tables**: Analyze spending patterns automatically

### 5. AI Processing
- Start AI session after CSV extraction
- Use natural language to:
  - Filter transactions: "Show only expenses above $50"
  - Categorize: "Categorize all restaurant expenses"
  - Transform: "Remove duplicate entries"
  - Analyze: "Show me the top 5 expense categories"

## Security Features

- **Client-Side PDF Processing**: Bank statements never leave your device
- **OAuth Authentication**: Secure, passwordless login
- **API Key Encryption**: Mistral API keys stored securely
- **Session Management**: Secure cookie-based sessions
- **Input Validation**: All user inputs are validated
- **Rate Limiting**: AI API calls are rate-limited

## File Structure

```
expenses-app/
├── app.py                 # Main Flask application
├── models.py             # Database models and schema
├── requirements.txt      # Python dependencies
├── render.yaml          # Render.com deployment config
├── README.md            # This file
├── templates/           # Jinja2 templates
│   ├── base.html        # Base template
│   ├── index.html       # Homepage
│   ├── settings.html    # User settings
│   ├── dashboard_list.html # Dashboard overview
│   └── dashboard_view.html # Individual dashboard
└── static/              # Static assets
    ├── css/
    │   └── style.css    # Custom styles
    └── js/
        ├── main.js      # Core JavaScript utilities
        └── dashboard.js # Dashboard-specific functionality
```

## API Endpoints

### Authentication
- `GET /` - Homepage
- `GET /login` - Initiate Google OAuth
- `GET /auth/callback` - OAuth callback
- `GET /logout` - Logout

### Dashboard Management
- `GET /dashboard` - List user dashboards
- `POST /api/dashboard/create` - Create new dashboard
- `GET /dashboard/<id>` - View specific dashboard

### AI Processing
- `POST /api/dashboard/<id>/ai/session` - Create AI session
- `POST /api/dashboard/<id>/ai/process` - Process CSV with AI

### Expense Management
- `GET /api/dashboard/<id>/expenses` - Get expenses
- `POST /api/dashboard/<id>/expenses` - Create expense
- `GET /api/dashboard/<id>/pivot` - Get pivot data

## Customization

### Adding New Expense Categories
Edit the `EXPENSE_CATEGORIES` list in `models.py`:

```python
EXPENSE_CATEGORIES = [
    'car', 'gas', 'grocery', 'home exp', 'home setup', 'gym', 
    'hospital', 'misc', 'rent', 'mortgage', 'restaurants', 
    'service', 'shopping', 'transport', 'utilities', 'vacation',
    'your-new-category'  # Add new categories here
]
```

### Changing AI Provider
Modify the `call_mistral_api` function in `app.py` to integrate with other AI providers like OpenAI, Anthropic, etc.

### Database Migration
To upgrade from SQLite to PostgreSQL:
1. Update `SQLALCHEMY_DATABASE_URI` in `app.py`
2. Install PostgreSQL dependencies
3. Run database migrations

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For issues and questions:
1. Check the documentation
2. Search existing issues
3. Create a new issue with detailed information

## Roadmap

- [ ] Real-time collaboration features
- [ ] Advanced PDF table extraction
- [ ] Export functionality (Excel, PDF reports)
- [ ] Mobile app companion
- [ ] Advanced analytics and charts
- [ ] Multi-currency support
- [ ] Budget tracking and alerts
