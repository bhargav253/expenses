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

### 🔒 Secure Server-Side PDF Processing
- Server-side PDF text extraction using Camelot and PyPDF
- Multiple extraction methods (Camelot for tables, PyPDF for text)
- Page-specific extraction support
- Secure file upload validation and MIME type checking

### 🤖 AI-Powered Data Processing
- Multiple AI provider support (DeepSeek, Mistral, OpenAI)
- Conversational PDF processing with context retention
- Natural language chat interface for CSV manipulation
- Context-aware conversations with conversation history
- CSV transformation, filtering, and categorization

### 📈 Interactive Expense Management
- **Monthly View**: Google Sheets-like editing with Handsontable.js
- **Yearly View**: Read-only summaries with DataTables.js
- **Category System**: Predefined expense categories
- **Pivot Tables**: Automatic expense analysis by month and category

### 🛡️ Security & Privacy
- Server-side PDF processing with secure file upload validation
- Encrypted API key storage
- Rate limiting for AI API calls
- Secure OAuth implementation
- Comprehensive security headers and input validation

## Technology Stack

### Backend
- **Python Flask** - Web framework
- **SQLite** - Database (easily upgradable to PostgreSQL)
- **Authlib** - OAuth authentication
- **Requests** - HTTP client for AI API
- **Standalone ticker worker** - DB-backed Finnhub ingestion for screener/watchlist data

### Frontend
- **Bootstrap 5** - Responsive UI framework
- **Handsontable.js** - Interactive spreadsheet editing
- **DataTables.js** - Advanced table functionality
- **Vanilla JavaScript** - Custom functionality
- **Debug Utility** - Conditional logging for development

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
- PDF processing happens server-side with Camelot and PyPDF
- Structured logging to `logs/app.log` with JSON format

### Screener Worker

The investing screener now supports a separate ingestion worker process:
- the web app reads ticker snapshots from the app DB
- the worker refreshes ticker history, intraday bars, fundamentals, and latest snapshots
- new ticker symbols are queued into fetch state when they are seeded or added by users

Required env var for worker-backed ingestion:
- `FINNHUB_API_KEY`

Run the web app locally:
```bash
python app.py
```

Run the ticker worker locally in another shell:
```bash
python ticker_worker.py
```

Run a single worker pass locally:
```bash
TICKER_WORKER_ONCE=true python ticker_worker.py
```

### Cloud Deployment (Render.com)

1. **Fork this repository**

2. **Create a new Web Service on Render**
   - Connect your GitHub repository
   - Use the following settings:
     - **Build Command**: `pip install -r requirements.txt`
     - **Start Command**: `gunicorn app:app`

3. **Create a separate Worker Service on Render**
   - Same repository and build command
   - **Start Command**: `python ticker_worker.py`
   - This process should point at the same database as the web service
   - Only one worker loop should be active; the app enforces this with a DB lease row

4. **Configure environment variables**
   - `SECRET_KEY`: Generate a secure random key
   - `GOOGLE_CLIENT_ID`: Your Google OAuth client ID
   - `GOOGLE_CLIENT_SECRET`: Your Google OAuth client secret
   - `FINNHUB_API_KEY`: Finnhub API key used by the ticker ingestion worker
   - `FINNHUB_RATE_LIMIT_PER_MINUTE`: Optional worker-side central rate budget
   - `TICKER_WORKER_SLEEP_SECONDS`: Optional idle sleep interval for the worker loop

5. **Deploy**
   - Render will automatically deploy your application

### Render Runtime Model

When hosted on Render, the intended investing flow is:
- the `web` service serves Flask routes and reads screener/watchlist data from DB tables
- the `worker` service runs `ticker_worker.py` continuously
- both services connect to the same database
- when a user adds a new ticker, the web app creates or reuses the global asset row and marks fetch-state rows as pending
- the worker sees that pending work, fetches Finnhub data, stores bars/fundamentals/snapshots, and updates retry state
- subsequent screener/watchlist page loads read the refreshed snapshot rows without making per-request Finnhub calls

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
- Upload bank statement PDFs (processed server-side with Camelot/PyPDF)
- Choose extraction method and page numbers
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

### 🔒 Enhanced Security Implementation
- **Flask-Talisman**: Security headers (HSTS, CSP, X-Frame-Options, Referrer Policy)
- **Flask-Limiter**: Rate limiting for API endpoints (PDF upload, AI processing, login)
- **File Upload Security**: MIME type validation, file size limits, path traversal protection
- **Structured Logging**: JSON-formatted logs with sensitive data redaction
- **Input Validation**: Server-side validation for all user inputs and Handsontable edits
- **Formula Injection Protection**: CSV export sanitization to prevent Excel formula injection
- **Secure Cookies**: HTTPOnly, Secure, SameSite cookie flags
- **Permission System**: Role-based access control with private/public edit modes

### 🛡️ Privacy & Data Protection
- **Server-Side PDF Processing**: Secure file upload with validation and MIME type checking
- **OAuth Authentication**: Secure, passwordless login
- **API Key Encryption**: AI provider API keys stored securely
- **Session Management**: Secure cookie-based sessions
- **Rate Limiting**: AI API calls are rate-limited to prevent abuse

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
