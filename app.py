from flask import Flask, render_template, redirect, url_for, session, request, jsonify, flash, make_response
from flask_talisman import Talisman
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from extensions import db
from authlib.integrations.flask_client import OAuth
from flask_wtf import CSRFProtect
from flask_wtf.csrf import CSRFError, generate_csrf
import os
from datetime import datetime, timedelta
import json
from pathlib import Path
import threading
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
from sqlalchemy import func, inspect, text
from sqlalchemy.exc import OperationalError

from expense_agent import run_expense_analytics_agent
from market_data import MarketDataError, MarketDataService, TradingViewScreenerError, TradingViewWatchlistScreenerService, normalize_symbol
from ticker_ingestion import enqueue_asset_refresh

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
MARKET_DATA_SERVICE = None
TRADINGVIEW_SCREENER_SERVICE = None


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


def get_market_data_service():
    global MARKET_DATA_SERVICE
    if MARKET_DATA_SERVICE is None:
        MARKET_DATA_SERVICE = MarketDataService()
    return MARKET_DATA_SERVICE


def get_tradingview_screener_service():
    global TRADINGVIEW_SCREENER_SERVICE
    if TRADINGVIEW_SCREENER_SERVICE is None:
        TRADINGVIEW_SCREENER_SERVICE = TradingViewWatchlistScreenerService()
    return TRADINGVIEW_SCREENER_SERVICE


DEFAULT_SCREENER_WATCHLIST_NAME = 'Default'
DEFAULT_SCREENER_WATCHLIST_DESCRIPTION = 'Broad stock universe used by the faceted screener.'
DEFAULT_SAVED_SCREENER_NAME = 'Default Stock Screener'
DEFAULT_SCREENER_MAX_CRITERIA = 5
VISIBLE_REFRESH_SYNC_BATCH_SIZE = 10
DEFAULT_WATCHLIST_FILE = Path(app.root_path) / 'next_plan' / 'screener' / 'default_watchlist.txt'
DEFAULT_SCREENER_SYMBOLS = None
BACKGROUND_WATCHLIST_REFRESH_JOBS = {}
BACKGROUND_VISIBLE_REFRESH_JOBS = {}
BACKGROUND_WATCHLIST_REFRESH_LOCK = threading.Lock()


def get_dashboard_member_or_none(dashboard_id, user_id):
    return DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=user_id
    ).first()


def load_default_screener_symbols():
    global DEFAULT_SCREENER_SYMBOLS
    if DEFAULT_SCREENER_SYMBOLS is not None:
        return DEFAULT_SCREENER_SYMBOLS

    symbols = []
    seen = set()
    if DEFAULT_WATCHLIST_FILE.exists():
        for line in DEFAULT_WATCHLIST_FILE.read_text(encoding='utf-8').splitlines():
            symbol = (line or '').strip().upper()
            if not symbol or symbol in seen:
                continue
            seen.add(symbol)
            symbols.append(symbol)

    DEFAULT_SCREENER_SYMBOLS = symbols
    return DEFAULT_SCREENER_SYMBOLS


def is_default_screener_watchlist(watchlist):
    return bool(watchlist and watchlist.name == DEFAULT_SCREENER_WATCHLIST_NAME)


def ensure_default_screener_watchlist(dashboard_id, created_by):
    watchlist = Watchlist.query.filter_by(
        dashboard_id=dashboard_id,
        name=DEFAULT_SCREENER_WATCHLIST_NAME
    ).first()
    created = False
    if watchlist is None:
        watchlist = Watchlist(
            dashboard_id=dashboard_id,
            created_by=created_by,
            name=DEFAULT_SCREENER_WATCHLIST_NAME,
            description=DEFAULT_SCREENER_WATCHLIST_DESCRIPTION
        )
        db.session.add(watchlist)
        db.session.flush()
        created = True

    symbols = load_default_screener_symbols()
    if not symbols:
        if created:
            db.session.commit()
        return watchlist

    existing_assets = Asset.query.filter(Asset.symbol.in_(symbols)).all()
    asset_map = {asset.symbol: asset for asset in existing_assets}
    missing_symbols = [symbol for symbol in symbols if symbol not in asset_map]
    if missing_symbols:
        db.session.add_all([
            Asset(symbol=symbol, asset_type='equity', added_source='seed', status='active')
            for symbol in missing_symbols
        ])
        db.session.flush()
        existing_assets = Asset.query.filter(Asset.symbol.in_(symbols)).all()
        asset_map = {asset.symbol: asset for asset in existing_assets}
        created = True

    for asset in asset_map.values():
        enqueue_asset_refresh(asset, include_backfill=False)
        created = True

    existing_asset_ids = {
        row.asset_id
        for row in WatchlistItem.query.filter_by(watchlist_id=watchlist.id).all()
    }
    new_items = []
    for symbol in symbols:
        asset = asset_map.get(symbol)
        if not asset or asset.id in existing_asset_ids:
            continue
        new_items.append(
            WatchlistItem(
                watchlist_id=watchlist.id,
                asset_id=asset.id,
                added_by=created_by,
                position_status='universe'
            )
        )
    if new_items:
        db.session.add_all(new_items)
        created = True

    watchlist_id = watchlist.id
    if created:
        db.session.commit()
        return Watchlist.query.get(watchlist_id)
    return watchlist


def ensure_default_screener_definition(dashboard_id, created_by, watchlist_id):
    screener = ScreenerDefinition.query.filter_by(
        dashboard_id=dashboard_id,
        name=DEFAULT_SAVED_SCREENER_NAME,
        is_archived=False
    ).first()
    if screener:
        return screener

    screener = ScreenerDefinition(
        dashboard_id=dashboard_id,
        created_by=created_by,
        name=DEFAULT_SAVED_SCREENER_NAME,
        description='Faceted stock screener over the default universe.',
        filters_json=json.dumps({
            'watchlist_id': watchlist_id,
            'criteria': []
        }),
        sort_json=json.dumps({
            'by': 'market_cap',
            'direction': 'desc'
        })
    )
    db.session.add(screener)
    screener_id = screener.id
    if screener_id is None:
        db.session.flush()
        screener_id = screener.id
    db.session.commit()
    return ScreenerDefinition.query.get(screener_id)


def get_or_create_dashboard_settings(user_id, dashboard_id):
    ensure_user_dashboard_settings_schema()
    settings = UserDashboardSettings.query.filter_by(
        user_id=user_id,
        dashboard_id=dashboard_id
    ).first()
    if settings:
        return settings

    settings = UserDashboardSettings(
        user_id=user_id,
        dashboard_id=dashboard_id,
        edit_mode='private'
    )
    db.session.add(settings)
    db.session.commit()
    return settings


def ensure_user_dashboard_settings_schema():
    inspector_rows = db.session.execute(text("PRAGMA table_info(user_dashboard_settings)")).fetchall()
    if not inspector_rows:
        return

    existing_columns = {row[1] for row in inspector_rows}
    if 'selected_investing_watchlist_id' not in existing_columns:
        db.session.execute(text("ALTER TABLE user_dashboard_settings ADD COLUMN selected_investing_watchlist_id INTEGER"))
        db.session.commit()
        existing_columns.add('selected_investing_watchlist_id')
    if 'selected_investing_screener_id' not in existing_columns:
        db.session.execute(text("ALTER TABLE user_dashboard_settings ADD COLUMN selected_investing_screener_id INTEGER"))
        db.session.commit()


def resolve_selected_watchlist(dashboard_id, user_id, default_watchlist):
    settings = get_or_create_dashboard_settings(user_id, dashboard_id)
    selected_watchlist = None
    if settings.selected_investing_watchlist_id:
        selected_watchlist = Watchlist.query.filter_by(
            id=settings.selected_investing_watchlist_id,
            dashboard_id=dashboard_id
        ).first()

    if selected_watchlist is None:
        selected_watchlist = default_watchlist

    return settings, selected_watchlist


def resolve_selected_screener(dashboard_id, user_id, default_screener):
    settings = get_or_create_dashboard_settings(user_id, dashboard_id)
    selected_screener = None
    if settings.selected_investing_screener_id:
        selected_screener = ScreenerDefinition.query.filter_by(
            id=settings.selected_investing_screener_id,
            dashboard_id=dashboard_id,
            is_archived=False
        ).first()

    if selected_screener is None:
        selected_screener = default_screener

    return settings, selected_screener


def _serialize_legacy_market_snapshot(snapshot):
    if snapshot is None:
        return None
    return {
        'price': snapshot.price,
        'change_percent': snapshot.change_percent,
        'market_cap': snapshot.market_cap,
        'volume': snapshot.volume,
        'fetched_at': snapshot.fetched_at.isoformat() if snapshot.fetched_at else None
    }


def get_latest_ticker_snapshot_for_asset(asset):
    if asset is None:
        return None
    if asset.ticker_snapshot_latest:
        snapshot = asset.ticker_snapshot_latest
        return {
            'price': snapshot.last_price,
            'change_percent': snapshot.today_change_percent,
            'price_performance_5d': snapshot.price_performance_5d,
            'market_cap': snapshot.market_cap,
            'volume': snapshot.volume,
            'fetched_at': snapshot.quote_as_of.isoformat() if snapshot.quote_as_of else snapshot.updated_at.isoformat() if snapshot.updated_at else None
        }
    if asset.market_snapshots:
        latest_legacy_snapshot = sorted(
            asset.market_snapshots,
            key=lambda snapshot: (snapshot.snapshot_date, snapshot.fetched_at),
            reverse=True
        )[0]
        return _serialize_legacy_market_snapshot(latest_legacy_snapshot)
    return None


def get_watchlist_price_performance_map(asset_ids, window):
    if not asset_ids or window < 2:
        return {}

    ranked_bars = (
        db.session.query(
            TickerDailyBar.asset_id.label('asset_id'),
            TickerDailyBar.close.label('close_price'),
            func.row_number().over(
                partition_by=TickerDailyBar.asset_id,
                order_by=TickerDailyBar.bar_date.desc()
            ).label('row_num')
        )
        .filter(TickerDailyBar.asset_id.in_(asset_ids))
        .subquery()
    )

    rows = (
        db.session.query(
            ranked_bars.c.asset_id,
            ranked_bars.c.close_price,
            ranked_bars.c.row_num
        )
        .filter(ranked_bars.c.row_num.in_([1, window]))
        .all()
    )

    performance_map = {}
    grouped_rows = {}
    for asset_id, close_price, row_num in rows:
        grouped_rows.setdefault(asset_id, {})[row_num] = close_price

    for asset_id, close_points in grouped_rows.items():
        current_price = close_points.get(1)
        prior_price = close_points.get(window)
        if current_price in (None, 0) or prior_price in (None, 0):
            continue
        performance_map[asset_id] = ((current_price - prior_price) / prior_price) * 100.0

    return performance_map


def serialize_watchlist_item(item, performance_12d_map=None):
    latest_snapshot = get_latest_ticker_snapshot_for_asset(item.asset) if item.asset else None
    asset_symbol = item.asset.symbol if item.asset else None
    asset_name = item.asset.name if item.asset and item.asset.name else asset_symbol
    performance_12d = performance_12d_map.get(item.asset_id) if performance_12d_map else None

    if latest_snapshot is not None:
        latest_snapshot = {**latest_snapshot, 'price_performance_12d': performance_12d}

    return {
        'id': item.id,
        'symbol': asset_symbol,
        'asset_name': asset_name,
        'position_status': item.position_status,
        'thesis_summary': item.thesis_summary,
        'target_price': item.target_price,
        'invalidation_price': item.invalidation_price,
        'snapshot': latest_snapshot
    }


def serialize_watchlist(watchlist):
    asset_ids = [item.asset_id for item in watchlist.items if item.asset_id]
    performance_12d_map = get_watchlist_price_performance_map(asset_ids, 12)
    items = [serialize_watchlist_item(item, performance_12d_map=performance_12d_map) for item in watchlist.items]
    items.sort(
        key=lambda item: (
            item['snapshot']['market_cap']
            if item.get('snapshot') and item['snapshot'].get('market_cap') is not None
            else -1
        ),
        reverse=True,
    )
    return {
        'id': watchlist.id,
        'name': watchlist.name,
        'description': watchlist.description,
        'is_archived': watchlist.is_archived,
        'items': items
    }


def get_watchlist_cache_coverage(watchlist):
    item_asset_ids = [item.asset_id for item in watchlist.items if item.asset_id]
    total_items = len(item_asset_ids)
    if not item_asset_ids:
        return {'cached_count': 0, 'total_items': 0, 'missing_count': 0}

    cached_rows = (
        db.session.query(TickerSnapshotLatest.asset_id)
        .filter(TickerSnapshotLatest.asset_id.in_(item_asset_ids))
        .distinct()
        .all()
    )
    cached_asset_ids = {row[0] for row in cached_rows}
    cached_count = sum(1 for asset_id in item_asset_ids if asset_id in cached_asset_ids)
    return {
        'cached_count': cached_count,
        'total_items': total_items,
        'missing_count': total_items - cached_count
    }


def get_watchlist_priority_refresh_status(watchlist, item_ids=None):
    if watchlist is None:
        return {
            'is_running': False,
            'pending_count': 0,
            'queued_count': 0,
            'completed_count': 0,
            'total_count': 0,
        }

    selected_item_ids = set(item_ids or [])
    items = [
        item for item in watchlist.items
        if not selected_item_ids or item.id in selected_item_ids
    ]
    asset_ids = [item.asset_id for item in items if item.asset_id]
    if not asset_ids:
        return {
            'is_running': False,
            'pending_count': 0,
            'queued_count': 0,
            'completed_count': 0,
            'total_count': 0,
        }

    fetch_states = TickerFetchState.query.filter(TickerFetchState.asset_id.in_(asset_ids)).all()
    state_map = {state.asset_id: state for state in fetch_states}
    queued_count = sum(1 for asset_id in asset_ids if state_map.get(asset_id) and state_map[asset_id].priority_requested_at)
    pending_count = sum(
        1 for asset_id in asset_ids
        if state_map.get(asset_id) and (
            state_map[asset_id].is_intraday_pending
            or state_map[asset_id].is_fundamentals_pending
            or state_map[asset_id].is_backfill_pending
        )
    )
    total_count = len(asset_ids)
    return {
        'is_running': queued_count > 0,
        'pending_count': pending_count,
        'queued_count': queued_count,
        'completed_count': max(total_count - pending_count, 0),
        'total_count': total_count,
    }


def get_asset_priority_refresh_status(asset):
    if asset is None:
        return {
            'is_running': False,
            'has_error': False,
            'error': None,
            'symbol': None,
            'snapshot': None,
        }

    fetch_state = asset.ticker_fetch_state
    latest_snapshot = get_latest_ticker_snapshot_for_asset(asset)
    error_message = fetch_state.last_error_message if fetch_state and fetch_state.last_error_message else None
    return {
        'is_running': bool(fetch_state and fetch_state.priority_requested_at),
        'has_error': bool(error_message),
        'error': error_message,
        'symbol': asset.symbol,
        'snapshot': latest_snapshot,
        'last_success_at': fetch_state.last_success_at.isoformat() if fetch_state and fetch_state.last_success_at else None,
    }


def _watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id):
    return f'{dashboard_id}:{user_id}:{watchlist_id}'


def get_watchlist_refresh_job(dashboard_id, user_id, watchlist_id):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        return BACKGROUND_WATCHLIST_REFRESH_JOBS.get(_watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id))


def set_watchlist_refresh_job(dashboard_id, user_id, watchlist_id, payload):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        BACKGROUND_WATCHLIST_REFRESH_JOBS[_watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id)] = payload


def update_watchlist_refresh_job(dashboard_id, user_id, watchlist_id, **updates):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        key = _watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id)
        job = BACKGROUND_WATCHLIST_REFRESH_JOBS.get(key, {}).copy()
        job.update(updates)
        BACKGROUND_WATCHLIST_REFRESH_JOBS[key] = job
        return job


def get_visible_refresh_job(dashboard_id, user_id, watchlist_id):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        return BACKGROUND_VISIBLE_REFRESH_JOBS.get(_watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id))


def set_visible_refresh_job(dashboard_id, user_id, watchlist_id, payload):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        BACKGROUND_VISIBLE_REFRESH_JOBS[_watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id)] = payload


def update_visible_refresh_job(dashboard_id, user_id, watchlist_id, **updates):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        key = _watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id)
        job = BACKGROUND_VISIBLE_REFRESH_JOBS.get(key, {}).copy()
        job.update(updates)
        BACKGROUND_VISIBLE_REFRESH_JOBS[key] = job
        return job


def clear_visible_refresh_job(dashboard_id, user_id, watchlist_id):
    with BACKGROUND_WATCHLIST_REFRESH_LOCK:
        BACKGROUND_VISIBLE_REFRESH_JOBS.pop(_watchlist_refresh_job_key(dashboard_id, user_id, watchlist_id), None)


def run_background_watchlist_cache_refresh(dashboard_id, user_id, watchlist_id):
    with app.app_context():
        watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
        if not watchlist:
            update_watchlist_refresh_job(
                dashboard_id,
                user_id,
                watchlist_id,
                is_running=False,
                completed_at=datetime.utcnow().isoformat(),
                error='Watchlist not found'
            )
            return

        coverage = get_watchlist_cache_coverage(watchlist)
        cached_asset_ids = {
            row[0] for row in (
                db.session.query(MarketSnapshot.asset_id)
                .filter(MarketSnapshot.asset_id.in_([item.asset_id for item in watchlist.items if item.asset_id]))
                .distinct()
                .all()
            )
        }
        items_to_refresh = [item for item in watchlist.items if item.asset_id and item.asset_id not in cached_asset_ids]
        total_to_refresh = len(items_to_refresh)
        update_watchlist_refresh_job(
            dashboard_id,
            user_id,
            watchlist_id,
            is_running=True,
            total_to_refresh=total_to_refresh,
            processed_count=0,
            refreshed_count=0,
            failed_count=0,
            cached_count=coverage['cached_count'],
            total_items=coverage['total_items'],
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            error=None
        )

        service = MarketDataService()
        refreshed_count = 0
        failed_count = 0
        processed_count = 0
        cached_count = coverage['cached_count']
        for item in items_to_refresh:
            try:
                service.refresh_quote_snapshot(item.asset.symbol)
                service.refresh_fundamental_snapshot(item.asset.symbol)
                refreshed_count += 1
                cached_count += 1
            except Exception:
                db.session.rollback()
                failed_count += 1
            processed_count += 1
            update_watchlist_refresh_job(
                dashboard_id,
                user_id,
                watchlist_id,
                is_running=True,
                processed_count=processed_count,
                refreshed_count=refreshed_count,
                failed_count=failed_count,
                cached_count=cached_count,
                total_items=coverage['total_items']
            )

        update_watchlist_refresh_job(
            dashboard_id,
            user_id,
            watchlist_id,
            is_running=False,
            processed_count=processed_count,
            refreshed_count=refreshed_count,
            failed_count=failed_count,
            cached_count=cached_count,
            total_items=coverage['total_items'],
            completed_at=datetime.utcnow().isoformat()
        )


def run_background_visible_watchlist_refresh(dashboard_id, user_id, watchlist_id, item_ids):
    with app.app_context():
        watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
        if not watchlist:
            update_visible_refresh_job(
                dashboard_id,
                user_id,
                watchlist_id,
                is_running=False,
                error='Watchlist not found',
                completed_at=datetime.utcnow().isoformat()
            )
            return

        target_items = [item for item in watchlist.items if item.id in set(item_ids)]
        service = MarketDataService()
        processed_count = 0
        refreshed_count = 0
        failed_count = 0
        total_count = len(target_items)
        update_visible_refresh_job(
            dashboard_id,
            user_id,
            watchlist_id,
            is_running=True,
            total_count=total_count,
            pending_count=total_count,
            processed_count=0,
            refreshed_count=0,
            failed_count=0,
            started_at=datetime.utcnow().isoformat(),
            completed_at=None,
            error=None
        )

        for item in target_items:
            try:
                service.refresh_quote_snapshot(item.asset.symbol)
                service.refresh_fundamental_snapshot(item.asset.symbol)
                refreshed_count += 1
            except Exception:
                db.session.rollback()
                failed_count += 1
            processed_count += 1
            update_visible_refresh_job(
                dashboard_id,
                user_id,
                watchlist_id,
                is_running=True,
                total_count=total_count,
                pending_count=max(total_count - processed_count, 0),
                processed_count=processed_count,
                refreshed_count=refreshed_count,
                failed_count=failed_count
            )

        update_visible_refresh_job(
            dashboard_id,
            user_id,
            watchlist_id,
            is_running=False,
            total_count=total_count,
            pending_count=0,
            processed_count=processed_count,
            refreshed_count=refreshed_count,
            failed_count=failed_count,
            completed_at=datetime.utcnow().isoformat()
        )


def serialize_trade_idea(idea):
    return {
        'id': idea.id,
        'asset_symbol': idea.asset.symbol if idea.asset else None,
        'asset_name': idea.asset.name if idea.asset else None,
        'title': idea.title,
        'idea_type': idea.idea_type,
        'status': idea.status,
        'thesis_summary': idea.thesis_summary,
        'entry_zone': idea.entry_zone,
        'target_1': idea.target_1,
        'invalidation': idea.invalidation,
        'time_horizon': idea.time_horizon,
        'confidence_score': idea.confidence_score,
        'created_at': idea.created_at.isoformat() if idea.created_at else None
    }


SCREENER_SORT_OPTIONS = {
    'change_percent': lambda row: row.get('change_percent') if row.get('change_percent') is not None else float('-inf'),
    'market_cap': lambda row: row.get('market_cap') if row.get('market_cap') is not None else float('-inf'),
    'volume': lambda row: row.get('volume') if row.get('volume') is not None else float('-inf'),
    'price': lambda row: row.get('price') if row.get('price') is not None else float('-inf'),
    'revenue_growth': lambda row: row.get('revenue_growth') if row.get('revenue_growth') is not None else float('-inf'),
    'eps_growth': lambda row: row.get('eps_growth') if row.get('eps_growth') is not None else float('-inf'),
    'forward_pe': lambda row: row.get('forward_pe') if row.get('forward_pe') is not None else float('inf'),
    'symbol': lambda row: row.get('symbol') or '',
    'pe_ratio': lambda row: row.get('pe_ratio') if row.get('pe_ratio') is not None else float('inf'),
    'today_change_percent': lambda row: row.get('today_change_percent') if row.get('today_change_percent') is not None else float('-inf'),
    'dividend_yield': lambda row: row.get('dividend_yield') if row.get('dividend_yield') is not None else float('-inf'),
    'annualized_return_1y': lambda row: row.get('annualized_return_1y') if row.get('annualized_return_1y') is not None else float('-inf'),
    'annualized_return_3y': lambda row: row.get('annualized_return_3y') if row.get('annualized_return_3y') is not None else float('-inf'),
    'annualized_return_5y': lambda row: row.get('annualized_return_5y') if row.get('annualized_return_5y') is not None else float('-inf'),
    'annualized_return_10y': lambda row: row.get('annualized_return_10y') if row.get('annualized_return_10y') is not None else float('-inf'),
    'price_performance_5d': lambda row: row.get('price_performance_5d') if row.get('price_performance_5d') is not None else float('-inf'),
    'price_performance_4w': lambda row: row.get('price_performance_4w') if row.get('price_performance_4w') is not None else float('-inf'),
    'price_performance_13w': lambda row: row.get('price_performance_13w') if row.get('price_performance_13w') is not None else float('-inf'),
    'price_performance_52w': lambda row: row.get('price_performance_52w') if row.get('price_performance_52w') is not None else float('-inf'),
    'revenue': lambda row: row.get('revenue') if row.get('revenue') is not None else float('-inf'),
    'peg_ratio': lambda row: row.get('peg_ratio') if row.get('peg_ratio') is not None else float('inf'),
    'industry': lambda row: (row.get('industry') or '').lower(),
    'days_since_52_week_high': lambda row: row.get('days_since_52_week_high') if row.get('days_since_52_week_high') is not None else float('inf'),
    'days_since_52_week_low': lambda row: row.get('days_since_52_week_low') if row.get('days_since_52_week_low') is not None else float('inf'),
    'percent_below_52_week_high': lambda row: row.get('percent_below_52_week_high') if row.get('percent_below_52_week_high') is not None else float('-inf'),
    'percent_above_52_week_low': lambda row: row.get('percent_above_52_week_low') if row.get('percent_above_52_week_low') is not None else float('-inf'),
    'total_return': lambda row: row.get('total_return') if row.get('total_return') is not None else float('-inf'),
    'percent_price_off_10day_sma': lambda row: row.get('percent_price_off_10day_sma') if row.get('percent_price_off_10day_sma') is not None else float('-inf'),
    'percent_price_off_20day_sma': lambda row: row.get('percent_price_off_20day_sma') if row.get('percent_price_off_20day_sma') is not None else float('-inf'),
    'percent_price_off_50day_sma': lambda row: row.get('percent_price_off_50day_sma') if row.get('percent_price_off_50day_sma') is not None else float('-inf'),
    'percent_price_off_200day_sma': lambda row: row.get('percent_price_off_200day_sma') if row.get('percent_price_off_200day_sma') is not None else float('-inf'),
}


def _band_option(option_id, label, min_value=None, max_value=None):
    return {
        'id': option_id,
        'label': label,
        'min': min_value,
        'max': max_value
    }


SCREENER_CRITERIA_REGISTRY = {
    'price': {
        'label': 'Price',
        'field': 'price',
        'type': 'bands',
        'bands': [
            _band_option('lt_10', '< $10', max_value=10),
            _band_option('10_25', '$10 - $25', min_value=10, max_value=25),
            _band_option('25_50', '$25 - $50', min_value=25, max_value=50),
            _band_option('50_100', '$50 - $100', min_value=50, max_value=100),
            _band_option('gt_100', '> $100', min_value=100),
        ]
    },
    'market_cap': {
        'label': 'Market Cap',
        'field': 'market_cap',
        'type': 'bands',
        'bands': [
            _band_option('lt_2b', '< 2B', max_value=2_000_000_000),
            _band_option('2b_10b', '2B - 10B', min_value=2_000_000_000, max_value=10_000_000_000),
            _band_option('10b_50b', '10B - 50B', min_value=10_000_000_000, max_value=50_000_000_000),
            _band_option('50b_200b', '50B - 200B', min_value=50_000_000_000, max_value=200_000_000_000),
            _band_option('gt_200b', '> 200B', min_value=200_000_000_000),
        ]
    },
    'industry': {
        'label': 'Industry',
        'field': 'industry',
        'type': 'text'
    },
    'pe_ratio': {
        'label': 'P/E',
        'field': 'pe_ratio',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0', max_value=0),
            _band_option('0_15', '0 - 15', min_value=0, max_value=15),
            _band_option('15_25', '15 - 25', min_value=15, max_value=25),
            _band_option('25_40', '25 - 40', min_value=25, max_value=40),
            _band_option('gt_40', '> 40', min_value=40),
        ]
    },
    'peg_ratio': {
        'label': 'PEG Ratio',
        'field': 'peg_ratio',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0', max_value=0),
            _band_option('0_2', '0 - 2', min_value=0, max_value=2),
            _band_option('2_3', '2 - 3', min_value=2, max_value=3),
            _band_option('3_4', '3 - 4', min_value=3, max_value=4),
            _band_option('gt_4', '> 4', min_value=4),
        ]
    },
    'revenue': {
        'label': 'Revenue',
        'field': 'revenue',
        'type': 'bands',
        'bands': [
            _band_option('lt_1b', '< 1B', max_value=1_000_000_000),
            _band_option('1b_10b', '1B - 10B', min_value=1_000_000_000, max_value=10_000_000_000),
            _band_option('10b_50b', '10B - 50B', min_value=10_000_000_000, max_value=50_000_000_000),
            _band_option('50b_200b', '50B - 200B', min_value=50_000_000_000, max_value=200_000_000_000),
            _band_option('gt_200b', '> 200B', min_value=200_000_000_000),
        ]
    },
    'dividend_yield': {
        'label': 'Dividend Yield',
        'field': 'dividend_yield',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_1', '0% - 1%', min_value=0, max_value=1),
            _band_option('1_2', '1% - 2%', min_value=1, max_value=2),
            _band_option('2_4', '2% - 4%', min_value=2, max_value=4),
            _band_option('gt_4', '> 4%', min_value=4),
        ]
    },
    'today_change_percent': {
        'label': 'Today Price Change',
        'field': 'today_change_percent',
        'type': 'bands',
        'bands': [
            _band_option('lt_m3', '< -3%', max_value=-3),
            _band_option('m3_0', '-3% - 0%', min_value=-3, max_value=0),
            _band_option('0_3', '0% - 3%', min_value=0, max_value=3),
            _band_option('3_7', '3% - 7%', min_value=3, max_value=7),
            _band_option('gt_7', '> 7%', min_value=7),
        ]
    },
    'percent_below_52_week_high': {
        'label': '% Below 52 Week High',
        'field': 'percent_below_52_week_high',
        'type': 'bands',
        'bands': [
            _band_option('lt_5', '< 5%', max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('20_35', '20% - 35%', min_value=20, max_value=35),
            _band_option('gt_35', '> 35%', min_value=35),
        ]
    },
    'percent_above_52_week_low': {
        'label': '% Above 52 Week Low',
        'field': 'percent_above_52_week_low',
        'type': 'bands',
        'bands': [
            _band_option('lt_5', '< 5%', max_value=5),
            _band_option('5_15', '5% - 15%', min_value=5, max_value=15),
            _band_option('15_30', '15% - 30%', min_value=15, max_value=30),
            _band_option('30_60', '30% - 60%', min_value=30, max_value=60),
            _band_option('gt_60', '> 60%', min_value=60),
        ]
    },
    'days_since_52_week_high': {
        'label': 'Days Since 52 Week High',
        'field': 'days_since_52_week_high',
        'type': 'bands',
        'bands': [
            _band_option('1d_5d', '1 - 5 Days', min_value=1, max_value=6),
            _band_option('1w_1m', '1 Week - 1 Month', min_value=6, max_value=31),
            _band_option('1m_1q', '1 Month - 1 Q', min_value=31, max_value=91),
            _band_option('1q_2q', '1 Q - 2 Q', min_value=91, max_value=181),
            _band_option('gt_2q', '> 2 Q', min_value=181),
        ]
    },
    'days_since_52_week_low': {
        'label': 'Days Since 52 Week Low',
        'field': 'days_since_52_week_low',
        'type': 'bands',
        'bands': [
            _band_option('1d_5d', '1 - 5 Days', min_value=1, max_value=6),
            _band_option('1w_1m', '1 Week - 1 Month', min_value=6, max_value=31),
            _band_option('1m_1q', '1 Month - 1 Q', min_value=31, max_value=91),
            _band_option('1q_2q', '1 Q - 2 Q', min_value=91, max_value=181),
            _band_option('gt_2q', '> 2 Q', min_value=181),
        ]
    },
    'total_return': {
        'label': 'Total Return',
        'field': 'total_return',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_50', '0% - 50%', min_value=0, max_value=50),
            _band_option('50_150', '50% - 150%', min_value=50, max_value=150),
            _band_option('150_300', '150% - 300%', min_value=150, max_value=300),
            _band_option('gt_300', '> 300%', min_value=300),
        ]
    },
    'annualized_return_1y': {
        'label': '1 Year Annualized',
        'field': 'annualized_return_1y',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('gt_20', '> 20%', min_value=20),
        ]
    },
    'annualized_return_3y': {
        'label': '3 Year Annualized',
        'field': 'annualized_return_3y',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('gt_20', '> 20%', min_value=20),
        ]
    },
    'annualized_return_5y': {
        'label': '5 Year Annualized',
        'field': 'annualized_return_5y',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('gt_20', '> 20%', min_value=20),
        ]
    },
    'annualized_return_10y': {
        'label': '10 Year Annualized',
        'field': 'annualized_return_10y',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('gt_20', '> 20%', min_value=20),
        ]
    },
    'price_performance_5d': {
        'label': 'Price Performance (5 Days)',
        'field': 'price_performance_5d',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_2', '0% - 2%', min_value=0, max_value=2),
            _band_option('2_5', '2% - 5%', min_value=2, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('gt_10', '> 10%', min_value=10),
        ]
    },
    'price_performance_4w': {
        'label': 'Price Performance (4 Weeks)',
        'field': 'price_performance_4w',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_2', '0% - 2%', min_value=0, max_value=2),
            _band_option('2_5', '2% - 5%', min_value=2, max_value=5),
            _band_option('5_15', '5% - 15%', min_value=5, max_value=15),
            _band_option('gt_15', '> 15%', min_value=15),
        ]
    },
    'price_performance_13w': {
        'label': 'Price Performance (13 Weeks)',
        'field': 'price_performance_13w',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('10_25', '10% - 25%', min_value=10, max_value=25),
            _band_option('gt_25', '> 25%', min_value=25),
        ]
    },
    'price_performance_52w': {
        'label': 'Price Performance (52 Weeks)',
        'field': 'price_performance_52w',
        'type': 'bands',
        'bands': [
            _band_option('lt_0', '< 0%', max_value=0),
            _band_option('0_10', '0% - 10%', min_value=0, max_value=10),
            _band_option('10_20', '10% - 20%', min_value=10, max_value=20),
            _band_option('20_40', '20% - 40%', min_value=20, max_value=40),
            _band_option('gt_40', '> 40%', min_value=40),
        ]
    },
    'percent_price_off_10day_sma': {
        'label': '% Price Off 10 Day SMA',
        'field': 'percent_price_off_10day_sma',
        'type': 'bands',
        'bands': [
            _band_option('lt_m5', '< -5%', max_value=-5),
            _band_option('m5_0', '-5% - 0%', min_value=-5, max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('gt_10', '> 10%', min_value=10),
        ]
    },
    'percent_price_off_20day_sma': {
        'label': '% Price Off 20 Day SMA',
        'field': 'percent_price_off_20day_sma',
        'type': 'bands',
        'bands': [
            _band_option('lt_m5', '< -5%', max_value=-5),
            _band_option('m5_0', '-5% - 0%', min_value=-5, max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('gt_10', '> 10%', min_value=10),
        ]
    },
    'percent_price_off_50day_sma': {
        'label': '% Price Off 50 Day SMA',
        'field': 'percent_price_off_50day_sma',
        'type': 'bands',
        'bands': [
            _band_option('lt_m5', '< -5%', max_value=-5),
            _band_option('m5_0', '-5% - 0%', min_value=-5, max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_10', '5% - 10%', min_value=5, max_value=10),
            _band_option('gt_10', '> 10%', min_value=10),
        ]
    },
    'percent_price_off_200day_sma': {
        'label': '% Price Off 200 Day SMA',
        'field': 'percent_price_off_200day_sma',
        'type': 'bands',
        'bands': [
            _band_option('lt_m10', '< -10%', max_value=-10),
            _band_option('m10_0', '-10% - 0%', min_value=-10, max_value=0),
            _band_option('0_5', '0% - 5%', min_value=0, max_value=5),
            _band_option('5_15', '5% - 15%', min_value=5, max_value=15),
            _band_option('gt_15', '> 15%', min_value=15),
        ]
    },
}


def serialize_screener_criteria():
    criteria = []
    for criterion_id, definition in SCREENER_CRITERIA_REGISTRY.items():
        criteria.append({
            'id': criterion_id,
            'label': definition['label'],
            'type': definition['type'],
            'field': definition['field'],
            'bands': definition.get('bands', [])
        })
    return criteria


def serialize_screener_definition(definition):
    filters = {}
    sort = {}
    if definition.filters_json:
        try:
            filters = json.loads(definition.filters_json)
        except (TypeError, ValueError):
            filters = {}
    if definition.sort_json:
        try:
            sort = json.loads(definition.sort_json)
        except (TypeError, ValueError):
            sort = {}

    return {
        'id': definition.id,
        'name': definition.name,
        'description': definition.description,
        'filters': filters,
        'sort': sort,
        'is_archived': definition.is_archived,
        'created_at': definition.created_at.isoformat() if definition.created_at else None,
        'updated_at': definition.updated_at.isoformat() if definition.updated_at else None
    }


def _coerce_float(value):
    if value in (None, ''):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _coerce_int(value, default):
    if value in (None, ''):
        return default
    try:
        parsed = int(value)
        return parsed if parsed > 0 else default
    except (TypeError, ValueError):
        return default


def _coerce_bool(value):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {'1', 'true', 'yes', 'on'}
    return False


def _normalize_screener_criteria(criteria):
    normalized = []
    if not isinstance(criteria, list):
        return normalized

    for raw_criterion in criteria[:DEFAULT_SCREENER_MAX_CRITERIA]:
        if not isinstance(raw_criterion, dict):
            continue
        criterion_id = (raw_criterion.get('criterion_id') or raw_criterion.get('id') or '').strip()
        definition = SCREENER_CRITERIA_REGISTRY.get(criterion_id)
        if not definition:
            continue

        normalized_criterion = {'criterion_id': criterion_id, 'type': definition['type']}
        if definition['type'] == 'text':
            query = (raw_criterion.get('query') or '').strip()
            normalized_criterion['query'] = query
        else:
            valid_band_ids = {band['id'] for band in definition.get('bands', [])}
            selected_band_ids = [
                band_id for band_id in raw_criterion.get('selected_band_ids', [])
                if band_id in valid_band_ids
            ]
            normalized_criterion['selected_band_ids'] = selected_band_ids
        normalized.append(normalized_criterion)
    return normalized


def _row_matches_band(value, band):
    if value is None:
        return False
    min_value = band.get('min')
    max_value = band.get('max')
    if min_value is not None and value < min_value:
        return False
    if max_value is not None and value >= max_value:
        return False
    return True


def _apply_faceted_criteria(rows, criteria):
    filtered_rows = list(rows)
    for criterion in criteria:
        definition = SCREENER_CRITERIA_REGISTRY.get(criterion.get('criterion_id'))
        if not definition:
            continue
        field_name = definition['field']
        if definition['type'] == 'text':
            query = (criterion.get('query') or '').strip().lower()
            if not query:
                continue
            filtered_rows = [
                row for row in filtered_rows
                if query in str(row.get(field_name) or '').lower()
            ]
            continue

        selected_band_ids = criterion.get('selected_band_ids') or []
        if not selected_band_ids:
            continue
        band_map = {band['id']: band for band in definition.get('bands', [])}
        filtered_rows = [
            row for row in filtered_rows
            if any(
                _row_matches_band(row.get(field_name), band_map[band_id])
                for band_id in selected_band_ids
                if band_id in band_map
            )
        ]
    return filtered_rows


def normalize_screener_payload(data):
    data = data or {}
    filters = data.get('filters') if isinstance(data.get('filters'), dict) else data
    sort = data.get('sort') if isinstance(data.get('sort'), dict) else {}

    normalized_filters = {
        'watchlist_id': _coerce_int(filters.get('watchlist_id'), None),
        'symbol_query': (filters.get('symbol_query') or '').strip().upper(),
        'sector_query': (filters.get('sector_query') or '').strip(),
        'min_price': _coerce_float(filters.get('min_price')),
        'max_price': _coerce_float(filters.get('max_price')),
        'min_market_cap': _coerce_float(filters.get('min_market_cap')),
        'min_volume': _coerce_float(filters.get('min_volume')),
        'min_change_percent': _coerce_float(filters.get('min_change_percent')),
        'min_revenue_growth': _coerce_float(filters.get('min_revenue_growth')),
        'min_eps_growth': _coerce_float(filters.get('min_eps_growth')),
        'max_forward_pe': _coerce_float(filters.get('max_forward_pe')),
        'above_ma50': _coerce_bool(filters.get('above_ma50')),
        'above_ma200': _coerce_bool(filters.get('above_ma200')),
        'criteria': _normalize_screener_criteria(filters.get('criteria')),
    }
    normalized_sort = {
        'by': (sort.get('by') or data.get('sort_by') or 'market_cap').strip(),
        'direction': (sort.get('direction') or data.get('sort_direction') or 'desc').strip().lower()
    }
    if normalized_sort['by'] not in SCREENER_SORT_OPTIONS:
        normalized_sort['by'] = 'change_percent'
    if normalized_sort['direction'] not in {'asc', 'desc'}:
        normalized_sort['direction'] = 'desc'

    return {
        'filters': normalized_filters,
        'sort': normalized_sort,
        'limit': _coerce_int(data.get('limit'), None)
    }


def get_latest_snapshot_map(model, date_field_name):
    date_column = getattr(model, date_field_name)
    rows = model.query.order_by(model.asset_id.asc(), date_column.desc(), model.fetched_at.desc()).all()
    latest_rows = {}
    for row in rows:
        latest_rows.setdefault(row.asset_id, row)
    return latest_rows


def get_latest_ticker_snapshot_map(asset_ids=None):
    query = TickerSnapshotLatest.query
    if asset_ids is not None:
        query = query.filter(TickerSnapshotLatest.asset_id.in_(asset_ids))
    return {row.asset_id: row for row in query.all()}


def build_screener_row(asset, ticker_snapshot=None, fundamentals=None, market=None):
    if ticker_snapshot is not None:
        market_price = market.price if market and market.price is not None else ticker_snapshot.last_price
        market_volume = market.volume if market and market.volume is not None else ticker_snapshot.volume
        market_cap = market.market_cap if market and market.market_cap is not None else ticker_snapshot.market_cap
        avg_volume = market.avg_volume if market and market.avg_volume is not None else ticker_snapshot.avg_volume
        moving_average_50 = market.moving_average_50 if market and market.moving_average_50 is not None else ticker_snapshot.moving_average_50
        moving_average_200 = market.moving_average_200 if market and market.moving_average_200 is not None else ticker_snapshot.moving_average_200
        today_change_percent = market.change_percent if market and market.change_percent is not None else ticker_snapshot.today_change_percent
        pe_ratio = fundamentals.pe_ratio if fundamentals and fundamentals.pe_ratio is not None else ticker_snapshot.pe_ratio
        forward_pe = fundamentals.forward_pe if fundamentals and fundamentals.forward_pe is not None else ticker_snapshot.forward_pe
        revenue_growth = fundamentals.revenue_growth if fundamentals and fundamentals.revenue_growth is not None else ticker_snapshot.revenue_growth
        eps_growth = fundamentals.eps_growth if fundamentals and fundamentals.eps_growth is not None else ticker_snapshot.eps_growth
        percent_below_52_week_high = ticker_snapshot.percent_below_52_week_high
        if market and market.fifty_two_week_high not in (None, 0) and market_price is not None:
            percent_below_52_week_high = ((market.fifty_two_week_high - market_price) / market.fifty_two_week_high) * 100.0
        percent_above_52_week_low = ticker_snapshot.percent_above_52_week_low
        if market and market.fifty_two_week_low not in (None, 0) and market_price is not None:
            percent_above_52_week_low = ((market_price - market.fifty_two_week_low) / market.fifty_two_week_low) * 100.0
        percent_price_off_50day_sma = ticker_snapshot.percent_price_off_50day_sma
        if market_price is not None and moving_average_50 not in (None, 0):
            percent_price_off_50day_sma = ((market_price - moving_average_50) / moving_average_50) * 100.0
        percent_price_off_200day_sma = ticker_snapshot.percent_price_off_200day_sma
        if market_price is not None and moving_average_200 not in (None, 0):
            percent_price_off_200day_sma = ((market_price - moving_average_200) / moving_average_200) * 100.0
        return {
            'asset_id': asset.id,
            'symbol': asset.symbol,
            'name': asset.name,
            'asset_type': asset.asset_type,
            'sector': asset.sector,
            'price': market_price,
            'change_percent': today_change_percent,
            'market_cap': market_cap,
            'volume': market_volume,
            'avg_volume': avg_volume,
            'moving_average_50': moving_average_50,
            'moving_average_200': moving_average_200,
            'snapshot_fetched_at': market.fetched_at.isoformat() if market and market.fetched_at else ticker_snapshot.quote_as_of.isoformat() if ticker_snapshot.quote_as_of else ticker_snapshot.updated_at.isoformat() if ticker_snapshot.updated_at else None,
            'revenue_growth': revenue_growth,
            'eps_growth': eps_growth,
            'forward_pe': forward_pe,
            'fundamentals_fetched_at': fundamentals.fetched_at.isoformat() if fundamentals and fundamentals.fetched_at else ticker_snapshot.fundamentals_as_of.isoformat() if ticker_snapshot.fundamentals_as_of else None,
            'industry': asset.industry,
            'pe_ratio': pe_ratio,
            'peg_ratio': None,
            'revenue': ticker_snapshot.revenue,
            'dividend_yield': ticker_snapshot.dividend_yield,
            'today_change_percent': today_change_percent,
            'percent_below_52_week_high': percent_below_52_week_high,
            'percent_above_52_week_low': percent_above_52_week_low,
            'days_since_52_week_high': None,
            'days_since_52_week_low': None,
            'total_return': None,
            'annualized_return_1y': None,
            'annualized_return_3y': None,
            'annualized_return_5y': None,
            'annualized_return_10y': None,
            'price_performance_5d': None,
            'price_performance_4w': None,
            'price_performance_13w': None,
            'price_performance_52w': None,
            'percent_price_off_10day_sma': None,
            'percent_price_off_20day_sma': None,
            'percent_price_off_50day_sma': percent_price_off_50day_sma,
            'percent_price_off_200day_sma': percent_price_off_200day_sma,
        }

    return {
        'asset_id': asset.id,
        'symbol': asset.symbol,
        'name': asset.name,
        'asset_type': asset.asset_type,
        'sector': asset.sector,
        'price': market.price,
        'change_percent': market.change_percent,
        'market_cap': market.market_cap,
        'volume': market.volume,
        'avg_volume': market.avg_volume,
        'moving_average_50': market.moving_average_50,
        'moving_average_200': market.moving_average_200,
        'snapshot_fetched_at': market.fetched_at.isoformat() if market.fetched_at else None,
        'revenue_growth': fundamentals.revenue_growth if fundamentals else None,
        'eps_growth': fundamentals.eps_growth if fundamentals else None,
        'forward_pe': fundamentals.forward_pe if fundamentals else None,
        'fundamentals_fetched_at': fundamentals.fetched_at.isoformat() if fundamentals and fundamentals.fetched_at else None,
        'industry': asset.industry,
        'pe_ratio': fundamentals.pe_ratio if fundamentals else None,
        'peg_ratio': None,
        'revenue': None,
        'dividend_yield': None,
        'today_change_percent': market.change_percent,
        'percent_below_52_week_high': ((market.fifty_two_week_high - market.price) / market.fifty_two_week_high) * 100.0
        if market.price is not None and market.fifty_two_week_high not in (None, 0) else None,
        'percent_above_52_week_low': ((market.price - market.fifty_two_week_low) / market.fifty_two_week_low) * 100.0
        if market.price is not None and market.fifty_two_week_low not in (None, 0) else None,
        'days_since_52_week_high': None,
        'days_since_52_week_low': None,
        'total_return': None,
        'annualized_return_1y': None,
        'annualized_return_3y': None,
        'annualized_return_5y': None,
        'annualized_return_10y': None,
        'price_performance_5d': None,
        'price_performance_4w': None,
        'price_performance_13w': None,
        'price_performance_52w': None,
        'percent_price_off_10day_sma': None,
        'percent_price_off_20day_sma': None,
        'percent_price_off_50day_sma': ((market.price - market.moving_average_50) / market.moving_average_50) * 100.0
        if market.price is not None and market.moving_average_50 not in (None, 0) else None,
        'percent_price_off_200day_sma': ((market.price - market.moving_average_200) / market.moving_average_200) * 100.0
        if market.price is not None and market.moving_average_200 not in (None, 0) else None,
    }


def run_cached_screener_query(payload, asset_ids=None, watchlist=None):
    normalized = normalize_screener_payload(payload)
    filters = normalized['filters']
    ticker_snapshot_map = get_latest_ticker_snapshot_map(asset_ids)
    market_map = get_latest_snapshot_map(MarketSnapshot, 'snapshot_date')
    fundamental_map = get_latest_snapshot_map(FundamentalSnapshot, 'as_of_date')
    if not ticker_snapshot_map and not market_map:
        return {
            'filters': filters,
            'sort': normalized['sort'],
            'results': [],
            'count': 0,
            'total_matches': 0,
            'watchlist': watchlist
        }

    scoped_asset_ids = list(ticker_snapshot_map.keys()) if ticker_snapshot_map else list(market_map.keys())
    if asset_ids is not None:
        scoped_asset_ids = [asset_id for asset_id in scoped_asset_ids if asset_id in set(asset_ids)]
    if not scoped_asset_ids and asset_ids is None and market_map:
        scoped_asset_ids = list(market_map.keys())
    if not scoped_asset_ids:
        return {
            'filters': filters,
            'sort': normalized['sort'],
            'results': [],
            'count': 0,
            'total_matches': 0,
            'watchlist': watchlist
        }

    assets = Asset.query.filter(Asset.id.in_(scoped_asset_ids)).all()
    rows = []
    for asset in assets:
        ticker_snapshot = ticker_snapshot_map.get(asset.id)
        market = market_map.get(asset.id)
        if not ticker_snapshot and not market:
            continue
        fundamentals = fundamental_map.get(asset.id)
        row = build_screener_row(asset, ticker_snapshot=ticker_snapshot, fundamentals=fundamentals, market=market)

        if filters['symbol_query']:
            symbol_text = row['symbol'] or ''
            name_text = row['name'] or ''
            if filters['symbol_query'] not in symbol_text and filters['symbol_query'] not in name_text.upper():
                continue
        if filters['sector_query']:
            sector_text = (row['sector'] or '').lower()
            if filters['sector_query'].lower() not in sector_text:
                continue
        if filters['min_price'] is not None and (row['price'] is None or row['price'] < filters['min_price']):
            continue
        if filters['max_price'] is not None and (row['price'] is None or row['price'] > filters['max_price']):
            continue
        if filters['min_market_cap'] is not None and (row['market_cap'] is None or row['market_cap'] < filters['min_market_cap']):
            continue
        if filters['min_volume'] is not None and (row['volume'] is None or row['volume'] < filters['min_volume']):
            continue
        if filters['min_change_percent'] is not None and (row['change_percent'] is None or row['change_percent'] < filters['min_change_percent']):
            continue
        if filters['min_revenue_growth'] is not None and (row['revenue_growth'] is None or row['revenue_growth'] < filters['min_revenue_growth']):
            continue
        if filters['min_eps_growth'] is not None and (row['eps_growth'] is None or row['eps_growth'] < filters['min_eps_growth']):
            continue
        if filters['max_forward_pe'] is not None and (row['forward_pe'] is None or row['forward_pe'] > filters['max_forward_pe']):
            continue
        if filters['above_ma50'] and (row['price'] is None or row['moving_average_50'] is None or row['price'] <= row['moving_average_50']):
            continue
        if filters['above_ma200'] and (row['price'] is None or row['moving_average_200'] is None or row['price'] <= row['moving_average_200']):
            continue

        rows.append(row)

    rows = _apply_faceted_criteria(rows, filters['criteria'])

    reverse = normalized['sort']['direction'] == 'desc'
    rows.sort(key=SCREENER_SORT_OPTIONS[normalized['sort']['by']], reverse=reverse)
    limited_rows = rows[:normalized['limit']] if normalized['limit'] else rows
    return {
        'filters': filters,
        'sort': normalized['sort'],
        'results': limited_rows,
        'count': len(limited_rows),
        'total_matches': len(rows),
        'watchlist': watchlist
    }


def run_watchlist_cached_screener(dashboard_id, payload):
    normalized = normalize_screener_payload(payload)
    watchlist_id = normalized['filters'].get('watchlist_id')
    if not watchlist_id:
        return run_cached_screener_query(payload)

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return {
            'filters': normalized['filters'],
            'sort': normalized['sort'],
            'results': [],
            'count': 0,
            'total_matches': 0,
            'watchlist': None
        }

    asset_ids = [item.asset_id for item in watchlist.items if item.asset_id]
    return run_cached_screener_query(
        payload,
        asset_ids=asset_ids,
        watchlist={'id': watchlist.id, 'name': watchlist.name}
    )

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

def validate_safe_sql(sql_text: str) -> bool:
    """Basic guardrail to ensure generated SQL is read-only and scoped."""
    lowered = sql_text.strip().lower()
    # Autocorrect common AI typo missing leading 's'
    if lowered.startswith('elect '):
        lowered = 's' + lowered
    banned = ['insert', 'update', 'delete', 'drop', 'alter', 'truncate', 'create', ';', '--']
    if any(token in lowered for token in banned):
        return False
    # Must start with select
    if not lowered.strip().startswith('select'):
        return False
    # Only allow referencing expense table
    if ' expense' not in lowered:
        return False
    return True

def generate_ai_analytics_sql(user, prompt):
    """Ask the configured AI provider to produce a safe SELECT for analytics."""
    # Respect test mode / missing keys
    model_key = user.default_ai_provider or 'mistral'
    model_config = AI_MODELS.get(model_key)
    print(f"MC -> {model_config} | MK -> {model_key}")
    if not model_config:
        return None
    api_key = user.get_decrypted_api_key(model_config['api_key_field'])
    if not api_key:
        return None

    print("going in")
    
    url = model_config['api_url']
    model_name = model_config['model_name']
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json"
    }

    system_prompt = """
You are a SQL assistant for the "expense" table with columns: id, dashboard_id, user_id, date (YYYY-MM-DD), description, amount, category, user_name.
Return a JSON object with keys: chart_type (bar|pie|table), sql (SELECT ...), summary (short).
Rules:
- Only SELECT statements. No DML/DDL.
- Always alias the first column as label and the numeric aggregate as value.
- For bar charts, group by month: strftime('%Y-%m', date) as label, SUM(amount) as value, ordered by month.
- For pie charts, group by category: category as label, SUM(amount) as value.
- For tables, mirror the bar/pie grouping but still return label/value columns.
- Scope to the dashboard_id provided in the input.
- If the user mentions years, filter by those years.
- If the user mentions a category, filter category case-insensitively.
Respond ONLY with JSON, no prose.
"""

    user_message = f"""
User request: {prompt}
Dashboard scope: use dashboard_id = {{dashboard_id}}
Output JSON keys: chart_type, sql, summary.
Example SQL for bar: SELECT strftime('%Y-%m', date) as label, SUM(amount) as value FROM expense WHERE dashboard_id={{dashboard_id}} GROUP BY label ORDER BY label;
"""

    payload = {
        "model": model_name,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "temperature": 0.2,
        "max_tokens": 500
    }

    try:
        resp = requests.post(url, headers=headers, data=json.dumps(payload), timeout=20)
        resp.raise_for_status()
        data = resp.json()
        ai_message = data.get('choices', [{}])[0].get('message', {}).get('content', '')
        print(f"nice --> {ai_message}")
        parsed = None
        try:
            parsed = json.loads(ai_message)
        except Exception:
            # Try to extract JSON block if wrapped
            import re as _re
            match = _re.search(r'\{.*\}', ai_message, _re.DOTALL)
            if match:
                parsed = json.loads(match.group(0))
        if not parsed:
            return None
        sql_text = parsed.get('sql', '')
        chart_type = parsed.get('chart_type', 'bar')
        summary = parsed.get('summary', '')
        if not sql_text or not validate_safe_sql(sql_text):
            return None
        logger.info(f"AI analytics SQL generation succesful: {sql_text}")
        return {
            'sql': sql_text,
            'chart_type': chart_type,
            'summary': summary
        }
    except Exception as e:
        logger.error(f"AI analytics SQL generation failed: {e}")
        print(f"failed?")        
        return None

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
if not database_url and 'pytest' in sys.modules:
    database_url = 'sqlite:////tmp/expenses_pytest.db'

app.config['SQLALCHEMY_DATABASE_URI'] = database_url or 'sqlite:///expenses.db'
if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
    app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
        'connect_args': {
            'timeout': 30,
        }
    }
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
from models import User, Dashboard, DashboardMember, Expense, Category, UploadedFile, ChatSession, DashboardInvitation, UserDashboardSettings, PDFExtraction, EXPENSE_CATEGORIES, AnalyticsSession, Asset, Watchlist, WatchlistItem, TradeIdea, MarketSnapshot, FundamentalSnapshot, ScreenerDefinition, TickerFetchState, TickerSnapshotLatest, TickerDailyBar


def ensure_schema_compatibility():
    inspector = inspect(db.engine)

    def ensure_columns(table_name, columns):
        if not inspector.has_table(table_name):
            return
        existing_columns = {column['name'] for column in inspector.get_columns(table_name)}
        for column_name, column_type in columns:
            if column_name in existing_columns:
                continue
            db.session.execute(text(f"ALTER TABLE {table_name} ADD COLUMN {column_name} {column_type}"))
            db.session.commit()

    ensure_columns('asset', [
        ('status', "VARCHAR(32) DEFAULT 'active'"),
        ('added_source', "VARCHAR(32) DEFAULT 'user'"),
    ])
    ensure_columns('ticker_snapshot_latest', [
        ('peg_ratio', 'FLOAT'),
        ('days_since_52_week_high', 'INTEGER'),
        ('days_since_52_week_low', 'INTEGER'),
        ('sma_10', 'FLOAT'),
        ('sma_20', 'FLOAT'),
        ('price_performance_5d', 'FLOAT'),
        ('price_performance_4w', 'FLOAT'),
        ('price_performance_13w', 'FLOAT'),
        ('price_performance_52w', 'FLOAT'),
        ('annualized_return_1y', 'FLOAT'),
        ('annualized_return_3y', 'FLOAT'),
        ('annualized_return_5y', 'FLOAT'),
        ('annualized_return_10y', 'FLOAT'),
        ('total_return', 'FLOAT'),
        ('percent_price_off_10day_sma', 'FLOAT'),
        ('percent_price_off_20day_sma', 'FLOAT'),
    ])
    ensure_columns('ticker_fetch_state', [
        ('priority_requested_at', 'DATETIME'),
        ('last_market_refresh_at', 'DATETIME'),
        ('last_market_close_trade_date', 'DATE'),
        ('last_fundamentals_trade_date', 'DATE'),
    ])


# Initialize database tables
def init_db():
    with app.app_context():
        db.create_all()
        if app.config['SQLALCHEMY_DATABASE_URI'].startswith('sqlite:'):
            try:
                db.session.execute(text("PRAGMA journal_mode=WAL"))
                db.session.execute(text("PRAGMA busy_timeout = 30000"))
                db.session.commit()
            except OperationalError:
                db.session.rollback()
        ensure_schema_compatibility()
        logger.info("Database tables created successfully")

# Create tables on startup
init_db()

# Routes
@app.route('/')
def index():
    if 'user_id' in session:
        user_id = session['user_id']
        user_dashboards = DashboardMember.query.filter_by(user_id=user_id).all()
        dashboards = [member.dashboard for member in user_dashboards]
        return render_template('index.html', dashboards=dashboards)
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
            return redirect(url_for('index'))
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
        
    return redirect(url_for('index'))

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


@app.route('/investing')
def investing_list():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']
    user_dashboards = DashboardMember.query.filter_by(user_id=user_id).all()
    dashboards = [member.dashboard for member in user_dashboards]
    pending_invitations = DashboardInvitation.query.filter_by(
        invited_user_id=user_id,
        status='pending'
    ).all()

    return render_template('investment_list.html', dashboards=dashboards, pending_invitations=pending_invitations)

@app.route('/settings')
def settings():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    user = User.query.get(session['user_id'])
    next_url = request.args.get('next', '').strip()
    if not next_url.startswith('/'):
        next_url = url_for('index')
    return render_template('settings.html', user=user, back_url=next_url)

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

        # Delete investing workspace records scoped to this dashboard
        watchlists = Watchlist.query.filter_by(dashboard_id=dashboard_id).all()
        watchlist_ids = [watchlist.id for watchlist in watchlists]
        if watchlist_ids:
            WatchlistItem.query.filter(WatchlistItem.watchlist_id.in_(watchlist_ids)).delete(synchronize_session=False)
        Watchlist.query.filter_by(dashboard_id=dashboard_id).delete()
        TradeIdea.query.filter_by(dashboard_id=dashboard_id).delete()
        ScreenerDefinition.query.filter_by(dashboard_id=dashboard_id).delete()

        # Delete per-dashboard user settings
        UserDashboardSettings.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Delete uploaded files
        UploadedFile.query.filter_by(dashboard_id=dashboard_id).delete()
        
        # Delete chat sessions
        ChatSession.query.filter_by(dashboard_id=dashboard_id).delete()

        # Delete PDF extractions
        PDFExtraction.query.filter_by(dashboard_id=dashboard_id).delete()

        # Delete dashboard invitations
        DashboardInvitation.query.filter_by(dashboard_id=dashboard_id).delete()
        
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
    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    
    if not member:
        return "Access denied", 403
    
    dashboard = Dashboard.query.get(dashboard_id)
    current_year_month = datetime.now().strftime('%Y-%m')
    return render_template('dashboard_view.html', dashboard=dashboard, current_year_month=current_year_month)


@app.route('/dashboard/<int:dashboard_id>/investing')
def investing_workspace(dashboard_id):
    if 'user_id' not in session:
        return redirect(url_for('login'))

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])

    if not member:
        return "Access denied", 403

    default_watchlist = ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    default_screener = ensure_default_screener_definition(dashboard_id, session['user_id'], default_watchlist.id)
    _, selected_watchlist = resolve_selected_watchlist(dashboard_id, session['user_id'], default_watchlist)
    _, selected_screener = resolve_selected_screener(dashboard_id, session['user_id'], default_screener)
    dashboard = Dashboard.query.get(dashboard_id)
    watchlists = Watchlist.query.filter_by(dashboard_id=dashboard_id).order_by(Watchlist.created_at.desc()).all()
    serialized_watchlists = [serialize_watchlist(watchlist) for watchlist in watchlists]
    serialized_selected_watchlist = serialize_watchlist(selected_watchlist) if selected_watchlist else None
    trade_ideas = TradeIdea.query.filter_by(dashboard_id=dashboard_id).order_by(TradeIdea.created_at.desc()).all()
    serialized_trade_ideas = [serialize_trade_idea(idea) for idea in trade_ideas]
    screeners = ScreenerDefinition.query.filter_by(dashboard_id=dashboard_id, is_archived=False).order_by(ScreenerDefinition.updated_at.desc()).all()
    serialized_screeners = [serialize_screener_definition(screener) for screener in screeners]
    return render_template(
        'investing_workspace.html',
        dashboard=dashboard,
        watchlists=serialized_watchlists,
        selected_watchlist=serialized_selected_watchlist,
        trade_ideas=serialized_trade_ideas,
        screeners=serialized_screeners,
        selected_screener=serialize_screener_definition(selected_screener) if selected_screener else None,
        screener_criteria=serialize_screener_criteria(),
        default_screener_watchlist_id=default_watchlist.id
    )


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists', methods=['GET'])
def get_watchlists(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    watchlists = Watchlist.query.filter_by(dashboard_id=dashboard_id).order_by(Watchlist.created_at.desc()).all()
    return jsonify({'watchlists': [serialize_watchlist(watchlist) for watchlist in watchlists]})


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlist-selection', methods=['PUT'])
def update_selected_investing_watchlist(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    default_watchlist = ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    data = request.get_json() or {}
    watchlist_id = _coerce_int(data.get('watchlist_id'), None)

    if watchlist_id is None:
        selected_watchlist = default_watchlist
    else:
        selected_watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
        if not selected_watchlist:
            return jsonify({'error': 'Watchlist not found'}), 404

    settings = get_or_create_dashboard_settings(session['user_id'], dashboard_id)
    settings.selected_investing_watchlist_id = selected_watchlist.id
    db.session.commit()

    return jsonify({
        'message': 'Selected watchlist updated successfully',
        'selected_watchlist': serialize_watchlist(selected_watchlist)
    })


@app.route('/api/dashboard/<int:dashboard_id>/investing/screener-selection', methods=['PUT'])
def update_selected_investing_screener(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    default_watchlist = ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    default_screener = ensure_default_screener_definition(dashboard_id, session['user_id'], default_watchlist.id)
    data = request.get_json() or {}
    screener_id = _coerce_int(data.get('screener_id'), None)

    if screener_id is None:
        selected_screener = default_screener
    else:
        selected_screener = ScreenerDefinition.query.filter_by(
            id=screener_id,
            dashboard_id=dashboard_id,
            is_archived=False
        ).first()
        if not selected_screener:
            return jsonify({'error': 'Screener not found'}), 404

    settings = get_or_create_dashboard_settings(session['user_id'], dashboard_id)
    settings.selected_investing_screener_id = selected_screener.id
    db.session.commit()

    return jsonify({
        'message': 'Selected screener updated successfully',
        'selected_screener': serialize_screener_definition(selected_screener)
    })


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/cache-refresh', methods=['POST'])
def start_watchlist_cache_refresh(dashboard_id, watchlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    existing_job = get_watchlist_refresh_job(dashboard_id, session['user_id'], watchlist_id)
    if existing_job and existing_job.get('is_running'):
        return jsonify(existing_job), 202

    coverage = get_watchlist_cache_coverage(watchlist)
    job_payload = {
        'is_running': True,
        'processed_count': 0,
        'refreshed_count': 0,
        'failed_count': 0,
        'cached_count': coverage['cached_count'],
        'total_items': coverage['total_items'],
        'total_to_refresh': coverage['missing_count'],
        'started_at': datetime.utcnow().isoformat(),
        'completed_at': None,
        'error': None
    }
    set_watchlist_refresh_job(dashboard_id, session['user_id'], watchlist_id, job_payload)
    worker = threading.Thread(
        target=run_background_watchlist_cache_refresh,
        args=(dashboard_id, session['user_id'], watchlist_id),
        daemon=True
    )
    worker.start()
    return jsonify(job_payload), 202


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/cache-refresh-status', methods=['GET'])
def get_watchlist_cache_refresh_status(dashboard_id, watchlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    coverage = get_watchlist_cache_coverage(watchlist)
    job = get_watchlist_refresh_job(dashboard_id, session['user_id'], watchlist_id) or {}
    payload = {
        'is_running': bool(job.get('is_running')),
        'processed_count': job.get('processed_count', 0),
        'refreshed_count': job.get('refreshed_count', 0),
        'failed_count': job.get('failed_count', 0),
        'cached_count': coverage['cached_count'],
        'total_items': coverage['total_items'],
        'total_to_refresh': job.get('total_to_refresh', coverage['missing_count']),
        'started_at': job.get('started_at'),
        'completed_at': job.get('completed_at'),
        'error': job.get('error')
    }
    return jsonify(payload)


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/refresh-status', methods=['GET'])
def get_watchlist_visible_refresh_status(dashboard_id, watchlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    item_ids = request.args.getlist('item_id', type=int)
    return jsonify(get_watchlist_priority_refresh_status(watchlist, item_ids=item_ids))


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists', methods=['POST'])
def create_watchlist(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Watchlist name is required'}), 400

    watchlist = Watchlist(
        dashboard_id=dashboard_id,
        created_by=session['user_id'],
        name=name,
        description=(data.get('description') or '').strip()
    )
    db.session.add(watchlist)
    db.session.commit()
    return jsonify({'message': 'Watchlist created successfully', 'watchlist': serialize_watchlist(watchlist)}), 201


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/items', methods=['POST'])
def add_watchlist_item(dashboard_id, watchlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404
    target_watchlist_id = watchlist.id

    data = request.get_json() or {}
    symbol = (data.get('symbol') or '').strip()
    if not symbol:
        return jsonify({'error': 'Ticker symbol is required'}), 400

    try:
        service = get_market_data_service()
        asset = service.get_or_create_asset(symbol)
        enqueue_asset_refresh(asset, include_backfill=False)
        existing = WatchlistItem.query.filter_by(watchlist_id=target_watchlist_id, asset_id=asset.id).first()
        if existing:
            db.session.commit()
            return jsonify({'message': 'Asset already exists in watchlist', 'item': serialize_watchlist_item(existing)}), 200

        item = WatchlistItem(
            watchlist_id=target_watchlist_id,
            asset_id=asset.id,
            added_by=session['user_id'],
            position_status='watching',
            thesis_summary=(data.get('thesis_summary') or '').strip() or None
        )
        db.session.add(item)
        db.session.commit()
        item = WatchlistItem.query.get(item.id)
        return jsonify({'message': 'Asset added to watchlist', 'item': serialize_watchlist_item(item)}), 201
    except MarketDataError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to add watchlist item", extra={'dashboard_id': dashboard_id, 'user_id': session['user_id']})
        return jsonify({'error': f'Failed to add symbol: {exc}'}), 500


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/items/<int:item_id>', methods=['DELETE'])
def delete_watchlist_item(dashboard_id, watchlist_id, item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    item = WatchlistItem.query.filter_by(id=item_id, watchlist_id=watchlist_id).first()
    if not item:
        return jsonify({'error': 'Watchlist item not found'}), 404

    db.session.delete(item)
    db.session.commit()
    return jsonify({'message': 'Watchlist item removed successfully'})


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/items/<int:item_id>', methods=['PUT'])
def update_watchlist_item(dashboard_id, watchlist_id, item_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    item = WatchlistItem.query.filter_by(id=item_id, watchlist_id=watchlist_id).first()
    if not item:
        return jsonify({'error': 'Watchlist item not found'}), 404

    data = request.get_json() or {}
    thesis_summary = data.get('thesis_summary')
    if thesis_summary is not None:
        item.thesis_summary = thesis_summary.strip() or None

    db.session.commit()
    return jsonify({'message': 'Watchlist item updated successfully', 'item': serialize_watchlist_item(item)})


@app.route('/api/dashboard/<int:dashboard_id>/investing/watchlists/<int:watchlist_id>/refresh', methods=['POST'])
def refresh_watchlist(dashboard_id, watchlist_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    watchlist = Watchlist.query.filter_by(id=watchlist_id, dashboard_id=dashboard_id).first()
    if not watchlist:
        return jsonify({'error': 'Watchlist not found'}), 404

    data = request.get_json(silent=True) or {}
    requested_item_ids = {
        item_id for item_id in (data.get('item_ids') or [])
        if isinstance(item_id, int)
    }
    items_to_refresh = [
        item for item in watchlist.items
        if not requested_item_ids or item.id in requested_item_ids
    ]
    for item in items_to_refresh:
        if item.asset:
            enqueue_asset_refresh(item.asset, include_backfill=False, include_fundamentals=True, include_intraday=True, priority=True)

    db.session.commit()
    return jsonify({
        'message': f'Queued {len(items_to_refresh)} ticker{"s" if len(items_to_refresh) != 1 else ""} for priority refresh',
        'queued': [item.asset.symbol for item in items_to_refresh if item.asset],
        'requested_count': len(items_to_refresh),
        'pending_count': len(items_to_refresh),
        'status': get_watchlist_priority_refresh_status(watchlist, item_ids=[item.id for item in items_to_refresh]),
    })


@app.route('/api/dashboard/<int:dashboard_id>/investing/assets/<string:symbol>/refresh', methods=['POST'])
def refresh_investing_asset(symbol, dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    try:
        service = get_market_data_service()
        asset = service.get_or_create_asset(symbol)
        enqueue_asset_refresh(asset, include_backfill=False, include_fundamentals=True, include_intraday=True, priority=True)
        db.session.commit()
        return jsonify({
            'message': f'Queued {asset.symbol} for priority refresh',
            'asset': {
                'symbol': asset.symbol,
                'name': asset.name,
            }
        })
    except MarketDataError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to queue asset refresh", extra={'dashboard_id': dashboard_id, 'user_id': session['user_id']})
        return jsonify({'error': f'Failed to queue asset refresh: {exc}'}), 500


@app.route('/api/dashboard/<int:dashboard_id>/investing/assets/<string:symbol>/refresh-status', methods=['GET'])
def get_investing_asset_refresh_status(symbol, dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    normalized_symbol = normalize_symbol(symbol)
    asset = Asset.query.filter_by(symbol=normalized_symbol).first()
    if not asset:
        return jsonify({'error': 'Asset not found'}), 404

    return jsonify(get_asset_priority_refresh_status(asset))


@app.route('/api/dashboard/<int:dashboard_id>/investing/trade-ideas', methods=['GET'])
def get_trade_ideas(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    ideas = TradeIdea.query.filter_by(dashboard_id=dashboard_id).order_by(TradeIdea.created_at.desc()).all()
    return jsonify({'trade_ideas': [serialize_trade_idea(idea) for idea in ideas]})


@app.route('/api/dashboard/<int:dashboard_id>/investing/trade-ideas', methods=['POST'])
def create_trade_idea(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json() or {}
    symbol = (data.get('symbol') or '').strip()
    title = (data.get('title') or '').strip()
    if not symbol or not title:
        return jsonify({'error': 'Symbol and title are required'}), 400

    try:
        service = get_market_data_service()
        asset = service.get_or_create_asset(symbol)
        enqueue_asset_refresh(asset, include_backfill=False)
        idea = TradeIdea(
            dashboard_id=dashboard_id,
            asset_id=asset.id,
            created_by=session['user_id'],
            source_type='manual',
            idea_type=(data.get('idea_type') or 'watch').strip(),
            title=title,
            thesis_summary=(data.get('thesis_summary') or '').strip() or None,
            entry_zone=(data.get('entry_zone') or '').strip() or None,
            target_1=(data.get('target_1') or '').strip() or None,
            invalidation=(data.get('invalidation') or '').strip() or None,
            time_horizon=(data.get('time_horizon') or '').strip() or None,
            confidence_score=data.get('confidence_score')
        )
        db.session.add(idea)
        db.session.commit()
        idea = TradeIdea.query.get(idea.id)
        return jsonify({'message': 'Trade idea created successfully', 'trade_idea': serialize_trade_idea(idea)}), 201
    except MarketDataError as exc:
        db.session.rollback()
        return jsonify({'error': str(exc)}), 400
    except Exception as exc:
        db.session.rollback()
        logger.exception("Failed to create trade idea", extra={'dashboard_id': dashboard_id, 'user_id': session['user_id']})
        return jsonify({'error': f'Failed to create trade idea: {exc}'}), 500


@app.route('/api/dashboard/<int:dashboard_id>/investing/screeners', methods=['GET'])
def get_screeners(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    default_watchlist = ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    ensure_default_screener_definition(dashboard_id, session['user_id'], default_watchlist.id)
    screeners = (
        ScreenerDefinition.query.filter_by(dashboard_id=dashboard_id, is_archived=False)
        .order_by(ScreenerDefinition.updated_at.desc())
        .all()
    )
    return jsonify({'screeners': [serialize_screener_definition(screener) for screener in screeners]})


@app.route('/api/dashboard/<int:dashboard_id>/investing/screeners', methods=['POST'])
def create_screener(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    data = request.get_json() or {}
    name = (data.get('name') or '').strip()
    if not name:
        return jsonify({'error': 'Screener name is required'}), 400

    normalized = normalize_screener_payload(data)
    screener = ScreenerDefinition(
        dashboard_id=dashboard_id,
        created_by=session['user_id'],
        name=name,
        description=(data.get('description') or '').strip() or None,
        filters_json=json.dumps(normalized['filters']),
        sort_json=json.dumps(normalized['sort'])
    )
    db.session.add(screener)
    db.session.commit()
    return jsonify({'message': 'Screener saved successfully', 'screener': serialize_screener_definition(screener)}), 201


@app.route('/api/dashboard/<int:dashboard_id>/investing/screeners/run', methods=['POST'])
def run_screener(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    member = get_dashboard_member_or_none(dashboard_id, session['user_id'])
    if not member:
        return jsonify({'error': 'Access denied'}), 403

    default_watchlist = ensure_default_screener_watchlist(dashboard_id, session['user_id'])
    data = request.get_json() or {}
    screener_id = data.get('screener_id')
    if screener_id:
        definition = ScreenerDefinition.query.filter_by(
            id=screener_id,
            dashboard_id=dashboard_id,
            is_archived=False
        ).first()
        if not definition:
            return jsonify({'error': 'Screener not found'}), 404

        payload = {
            'filters': json.loads(definition.filters_json or '{}'),
            'sort': json.loads(definition.sort_json or '{}'),
            'limit': data.get('limit')
        }
    else:
        payload = data

    if isinstance(payload, dict) and not screener_id:
        filters_payload = payload.get('filters') if isinstance(payload.get('filters'), dict) else payload
        if filters_payload.get('watchlist_id') in (None, '', 0):
            filters_payload['watchlist_id'] = default_watchlist.id

    try:
        normalized = normalize_screener_payload(payload)
        if normalized['filters'].get('watchlist_id'):
            result = run_watchlist_cached_screener(dashboard_id, payload)
        else:
            result = run_cached_screener_query(payload)
        return jsonify(result)
    except TradingViewScreenerError as exc:
        return jsonify({'error': str(exc)}), 400


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

@app.route('/api/dashboard/<int:dashboard_id>/members/<int:user_id>', methods=['DELETE'])
def remove_dashboard_member(dashboard_id, user_id):
    """Remove a member from a dashboard. Only owners can remove, and the last owner cannot be removed."""
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401

    acting_user_id = session['user_id']

    # Ensure the requester is an owner
    owner_member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=acting_user_id,
        role='owner'
    ).first()
    if not owner_member:
        return jsonify({'error': 'Only dashboard owners can remove members'}), 403

    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=user_id
    ).first()
    if not member:
        return jsonify({'error': 'Member not found on this dashboard'}), 404

    # Prevent removing the last owner
    if member.role == 'owner':
        owner_count = DashboardMember.query.filter_by(
            dashboard_id=dashboard_id,
            role='owner'
        ).count()
        if owner_count <= 1:
            return jsonify({'error': 'Cannot remove the last owner of the dashboard'}), 400

    try:
        # Clean up per-user settings for this dashboard
        UserDashboardSettings.query.filter_by(
            dashboard_id=dashboard_id,
            user_id=user_id
        ).delete()

        db.session.delete(member)
        db.session.commit()

        return jsonify({'message': 'Member removed successfully'})
    except Exception as exc:
        db.session.rollback()
        logger.error(f"Failed to remove member: {exc}")
        return jsonify({'error': 'Failed to remove member'}), 500

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

# Analytics helper
def parse_analytics_prompt(prompt: str):
    text = (prompt or '').lower()
    years = re.findall(r'20\d{2}', text)
    years = sorted(set(years))
    categories = [c for c in EXPENSE_CATEGORIES if c.lower() in text]
    
    chart_type = 'bar'
    if any(k in text for k in ['percent', 'percentage', 'share', 'breakdown', 'vs', 'versus']):
        chart_type = 'pie'
    if any(k in text for k in ['table', 'list', 'grid', 'show table']):
        chart_type = 'table'
    
    target_category = categories[0] if categories else None
    
    return {
        'chart_type': chart_type,
        'years': years,
        'category': target_category,
        'categories': categories
    }

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


@app.route('/api/dashboard/<int:dashboard_id>/expenses/bulk', methods=['POST'])
def create_expenses_bulk(dashboard_id):
    """
    Create multiple expenses in one request to reduce client-side request bursts.
    Accepts JSON payload: {"expenses": [ {date, description, amount, category}, ... ]}
    """
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    payload = request.get_json() or {}
    expenses_payload = payload.get('expenses')
    
    if not isinstance(expenses_payload, list):
        return jsonify({'error': 'Invalid payload: "expenses" must be a list'}), 400
    
    saved = 0
    errors = []
    
    for idx, expense_data in enumerate(expenses_payload):
        try:
            validated = validate_expense_data(expense_data)
            expense = Expense(
                dashboard_id=dashboard_id,
                user_id=session['user_id'],
                date=datetime.strptime(validated['date'], '%Y-%m-%d').date(),
                description=validated['description'],
                amount=float(validated['amount']),
                category=validated.get('category', 'misc')
            )
            db.session.add(expense)
            saved += 1
        except ValueError as e:
            errors.append({'index': idx, 'error': str(e)})
        except Exception as e:
            errors.append({'index': idx, 'error': f'Unexpected error: {str(e)}'})
    
    if saved > 0:
        db.session.commit()
    else:
        db.session.rollback()
    
    logger.info(
        "Bulk expense import",
        extra={
            'user_id': session['user_id'],
            'dashboard_id': dashboard_id,
            'saved': saved,
            'errors': len(errors)
        }
    )
    
    return jsonify({
        'message': f'Bulk import completed: {saved} saved, {len(errors)} failed',
        'saved': saved,
        'errors': errors
    }), 200


@app.route('/api/dashboard/<int:dashboard_id>/analytics/query', methods=['POST'])
def analytics_query(dashboard_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    member = DashboardMember.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=session['user_id']
    ).first()
    if not member:
        return jsonify({'error': 'Access denied'}), 403
    
    data = request.get_json() or {}
    prompt = data.get('prompt', '')
    session_id = data.get('session_id')
    now_ts = datetime.utcnow()
    
    # Load or create analytics session
    analytics_session = None
    if session_id:
        analytics_session = AnalyticsSession.query.filter_by(
            session_id=session_id,
            dashboard_id=dashboard_id,
            user_id=session['user_id']
        ).first()
        if analytics_session and analytics_session.expires_at and analytics_session.expires_at < now_ts:
            analytics_session.status = 'expired'
            db.session.commit()
            analytics_session = None

    if not analytics_session:
        analytics_session = AnalyticsSession(
            session_id=str(uuid.uuid4()),
            dashboard_id=dashboard_id,
            user_id=session['user_id'],
            expires_at=now_ts + timedelta(hours=1)
        )
        db.session.add(analytics_session)
        db.session.commit()

    try:
        resp = run_expense_analytics_agent(
            dashboard_id=dashboard_id,
            prompt=prompt,
            user_id=session['user_id']
        )
        resp['session_id'] = analytics_session.session_id
        analytics_session.add_entry('user', prompt)
        analytics_session.add_entry('assistant', resp.get('summary', ''), summary=resp.get('request_type'))
        analytics_session.expires_at = now_ts + timedelta(hours=1)
        db.session.commit()
        return jsonify(resp)
    except Exception as exc:
        logger.exception(
            "Expense analytics agent failed",
            extra={'dashboard_id': dashboard_id, 'user_id': session['user_id']}
        )
        return jsonify({'error': f'Failed to analyze expenses: {exc}'}), 500

@app.route('/api/dashboard/<int:dashboard_id>/analytics/session/<string:session_id>', methods=['DELETE'])
def cancel_analytics_session(dashboard_id, session_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    sess = AnalyticsSession.query.filter_by(
        dashboard_id=dashboard_id,
        user_id=session['user_id'],
        session_id=session_id
    ).first()
    if not sess:
        return jsonify({'error': 'Session not found'}), 404
    
    db.session.delete(sess)
    db.session.commit()
    return jsonify({'message': 'Analytics context cleared'})

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

    # Load or create analytics session
    analytics_session = None
    if session_id:
        analytics_session = AnalyticsSession.query.filter_by(session_id=session_id, dashboard_id=dashboard_id, user_id=session['user_id']).first()
        # Expire if past
        if analytics_session and analytics_session.expires_at and analytics_session.expires_at < now_ts:
            analytics_session.status = 'expired'
            db.session.commit()
            analytics_session = None

    if not analytics_session:
        analytics_session = AnalyticsSession(
            session_id=str(uuid.uuid4()),
            dashboard_id=dashboard_id,
            user_id=session['user_id'],
            expires_at=now_ts + timedelta(hours=1)
        )
        db.session.add(analytics_session)
        db.session.commit()
    
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
