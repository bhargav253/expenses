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


def utc_today():
    return datetime.utcnow().date()

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
    newsapi_api_key = db.Column(db.String(255))
    default_ai_provider = db.Column(db.String(50), default='mistral')  # 'mistral', 'openai', 'anthropic', 'deepseek'
    newsapi_daily_limit = db.Column(db.Integer, default=100)
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
    watchlists = db.relationship('Watchlist', back_populates='dashboard')
    trade_ideas = db.relationship('TradeIdea', back_populates='dashboard')
    screener_definitions = db.relationship('ScreenerDefinition', back_populates='dashboard')

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


class Asset(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    symbol = db.Column(db.String(32), unique=True, nullable=False, index=True)
    name = db.Column(db.String(255))
    asset_type = db.Column(db.String(50), default='equity')
    exchange = db.Column(db.String(64))
    currency = db.Column(db.String(16), default='USD')
    sector = db.Column(db.String(128))
    industry = db.Column(db.String(128))
    is_active = db.Column(db.Boolean, default=True)
    status = db.Column(db.String(32), default='active')
    added_source = db.Column(db.String(32), default='user')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    market_snapshots = db.relationship('MarketSnapshot', back_populates='asset')
    fundamental_snapshots = db.relationship('FundamentalSnapshot', back_populates='asset')
    ticker_snapshot_latest = db.relationship('TickerSnapshotLatest', back_populates='asset', uselist=False)
    ticker_daily_bars = db.relationship('TickerDailyBar', back_populates='asset')
    ticker_intraday_bars = db.relationship('TickerIntradayBar', back_populates='asset')
    ticker_fundamentals_latest = db.relationship('TickerFundamentalsLatest', back_populates='asset', uselist=False)
    ticker_fetch_state = db.relationship('TickerFetchState', back_populates='asset', uselist=False)
    watchlist_items = db.relationship('WatchlistItem', back_populates='asset')
    trade_ideas = db.relationship('TradeIdea', back_populates='asset')


class Watchlist(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    is_archived = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard', back_populates='watchlists')
    creator = db.relationship('User')
    items = db.relationship('WatchlistItem', back_populates='watchlist')


class WatchlistItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    watchlist_id = db.Column(db.Integer, db.ForeignKey('watchlist.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    added_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    position_status = db.Column(db.String(50), default='watching')
    thesis_summary = db.Column(db.Text)
    bull_case = db.Column(db.Text)
    bear_case = db.Column(db.Text)
    target_price = db.Column(db.Float)
    invalidation_price = db.Column(db.Float)
    conviction_score = db.Column(db.Integer)
    time_horizon = db.Column(db.String(100))
    catalyst_date = db.Column(db.Date)
    notes = db.Column(db.Text)
    tags_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    watchlist = db.relationship('Watchlist', back_populates='items')
    asset = db.relationship('Asset', back_populates='watchlist_items')
    added_by_user = db.relationship('User')

    __table_args__ = (
        db.UniqueConstraint('watchlist_id', 'asset_id', name='unique_watchlist_asset'),
    )


class TradeIdea(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    source_type = db.Column(db.String(50), default='manual')
    idea_type = db.Column(db.String(50), default='watch')
    title = db.Column(db.String(255), nullable=False)
    thesis_summary = db.Column(db.Text)
    entry_zone = db.Column(db.String(255))
    target_1 = db.Column(db.String(255))
    target_2 = db.Column(db.String(255))
    invalidation = db.Column(db.String(255))
    time_horizon = db.Column(db.String(100))
    confidence_score = db.Column(db.Integer)
    catalysts = db.Column(db.Text)
    risks = db.Column(db.Text)
    status = db.Column(db.String(50), default='active')
    opened_at = db.Column(db.DateTime)
    closed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard', back_populates='trade_ideas')
    asset = db.relationship('Asset', back_populates='trade_ideas')
    creator = db.relationship('User')


class TradeAgentRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False, index=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    request_text = db.Column(db.Text)
    status = db.Column(db.String(50), default='completed')
    analysis_json = db.Column(db.Text)
    critic_json = db.Column(db.Text)
    warnings_json = db.Column(db.Text)
    data_freshness_json = db.Column(db.Text)
    generation_mode = db.Column(db.String(50), default='deterministic')
    provider_name = db.Column(db.String(50))
    model_name = db.Column(db.String(100))
    stage_usage_json = db.Column(db.Text)
    token_usage_json = db.Column(db.Text)
    created_trade_idea_id = db.Column(db.Integer, db.ForeignKey('trade_idea.id'))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard')
    asset = db.relationship('Asset')
    creator = db.relationship('User')
    created_trade_idea = db.relationship('TradeIdea', foreign_keys=[created_trade_idea_id])
    events = db.relationship('TradeAgentEvent', back_populates='run', cascade='all, delete-orphan')


class TradeAgentEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trade_agent_run_id = db.Column(db.Integer, db.ForeignKey('trade_agent_run.id'), nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False)
    event_payload_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    run = db.relationship('TradeAgentRun', back_populates='events')


class TrendScanRun(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False, index=True)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    scenario_prompt = db.Column(db.Text, nullable=False)
    source_modes_json = db.Column(db.Text)
    query_terms_json = db.Column(db.Text)
    ranked_results_json = db.Column(db.Text)
    warnings_json = db.Column(db.Text)
    summary_json = db.Column(db.Text)
    source_statuses_json = db.Column(db.Text)
    status = db.Column(db.String(50), default='completed')
    generation_mode = db.Column(db.String(50), default='deterministic')
    provider_name = db.Column(db.String(50))
    model_name = db.Column(db.String(100))
    token_usage_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard')
    creator = db.relationship('User')
    events = db.relationship('TrendScanEvent', back_populates='run', cascade='all, delete-orphan')


class TrendScanEvent(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    trend_scan_run_id = db.Column(db.Integer, db.ForeignKey('trend_scan_run.id'), nullable=False, index=True)
    event_type = db.Column(db.String(100), nullable=False)
    event_payload_json = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    run = db.relationship('TrendScanRun', back_populates='events')


class MarketSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False, default='yfinance')
    snapshot_date = db.Column(db.Date, nullable=False, default=utc_today)
    price = db.Column(db.Float)
    change_percent = db.Column(db.Float)
    market_cap = db.Column(db.Float)
    volume = db.Column(db.Float)
    avg_volume = db.Column(db.Float)
    fifty_two_week_high = db.Column(db.Float)
    fifty_two_week_low = db.Column(db.Float)
    moving_average_50 = db.Column(db.Float)
    moving_average_200 = db.Column(db.Float)
    raw_payload_json = db.Column(db.Text)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='market_snapshots')

    __table_args__ = (
        db.Index('idx_market_snapshot_asset_date_provider', 'asset_id', 'snapshot_date', 'provider'),
    )


class FundamentalSnapshot(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False)
    provider = db.Column(db.String(50), nullable=False, default='yfinance')
    as_of_date = db.Column(db.Date, nullable=False, default=utc_today)
    pe_ratio = db.Column(db.Float)
    forward_pe = db.Column(db.Float)
    price_to_sales = db.Column(db.Float)
    revenue_growth = db.Column(db.Float)
    eps_growth = db.Column(db.Float)
    gross_margin = db.Column(db.Float)
    operating_margin = db.Column(db.Float)
    free_cash_flow = db.Column(db.Float)
    debt_to_equity = db.Column(db.Float)
    return_on_equity = db.Column(db.Float)
    raw_payload_json = db.Column(db.Text)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='fundamental_snapshots')

    __table_args__ = (
        db.Index('idx_fundamental_snapshot_asset_date_provider', 'asset_id', 'as_of_date', 'provider'),
    )


class TickerSnapshotLatest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, unique=True, index=True)
    last_price = db.Column(db.Float)
    day_open = db.Column(db.Float)
    day_high = db.Column(db.Float)
    day_low = db.Column(db.Float)
    day_close = db.Column(db.Float)
    today_change_percent = db.Column(db.Float)
    market_cap = db.Column(db.Float)
    volume = db.Column(db.Float)
    avg_volume = db.Column(db.Float)
    pe_ratio = db.Column(db.Float)
    peg_ratio = db.Column(db.Float)
    forward_pe = db.Column(db.Float)
    price_to_sales = db.Column(db.Float)
    revenue_growth = db.Column(db.Float)
    eps_growth = db.Column(db.Float)
    revenue = db.Column(db.Float)
    dividend_yield = db.Column(db.Float)
    gross_margin = db.Column(db.Float)
    operating_margin = db.Column(db.Float)
    free_cash_flow = db.Column(db.Float)
    debt_to_equity = db.Column(db.Float)
    return_on_equity = db.Column(db.Float)
    fifty_two_week_high = db.Column(db.Float)
    fifty_two_week_low = db.Column(db.Float)
    days_since_52_week_high = db.Column(db.Integer)
    days_since_52_week_low = db.Column(db.Integer)
    sma_10 = db.Column(db.Float)
    sma_20 = db.Column(db.Float)
    moving_average_50 = db.Column(db.Float)
    moving_average_200 = db.Column(db.Float)
    price_performance_5d = db.Column(db.Float)
    price_performance_4w = db.Column(db.Float)
    price_performance_13w = db.Column(db.Float)
    price_performance_52w = db.Column(db.Float)
    annualized_return_1y = db.Column(db.Float)
    annualized_return_3y = db.Column(db.Float)
    annualized_return_5y = db.Column(db.Float)
    annualized_return_10y = db.Column(db.Float)
    total_return = db.Column(db.Float)
    percent_price_off_10day_sma = db.Column(db.Float)
    percent_price_off_20day_sma = db.Column(db.Float)
    percent_below_52_week_high = db.Column(db.Float)
    percent_above_52_week_low = db.Column(db.Float)
    percent_price_off_50day_sma = db.Column(db.Float)
    percent_price_off_200day_sma = db.Column(db.Float)
    quote_as_of = db.Column(db.DateTime)
    fundamentals_as_of = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='ticker_snapshot_latest')


class TickerDailyBar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, index=True)
    bar_date = db.Column(db.Date, nullable=False, index=True)
    open = db.Column(db.Float)
    high = db.Column(db.Float)
    low = db.Column(db.Float)
    close = db.Column(db.Float)
    volume = db.Column(db.Float)
    source = db.Column(db.String(50), default='finnhub')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='ticker_daily_bars')

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'bar_date', name='unique_ticker_daily_bar_asset_date'),
    )


class TickerIntradayBar(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, index=True)
    bar_timestamp = db.Column(db.DateTime, nullable=False, index=True)
    open = db.Column(db.Float)
    high = db.Column(db.Float)
    low = db.Column(db.Float)
    close = db.Column(db.Float)
    volume = db.Column(db.Float)
    source = db.Column(db.String(50), default='finnhub')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='ticker_intraday_bars')

    __table_args__ = (
        db.UniqueConstraint('asset_id', 'bar_timestamp', name='unique_ticker_intraday_bar_asset_timestamp'),
    )


class TickerFundamentalsLatest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, unique=True, index=True)
    market_cap = db.Column(db.Float)
    pe_ratio = db.Column(db.Float)
    forward_pe = db.Column(db.Float)
    peg_ratio = db.Column(db.Float)
    price_to_sales = db.Column(db.Float)
    revenue_growth = db.Column(db.Float)
    eps_growth = db.Column(db.Float)
    gross_margin = db.Column(db.Float)
    operating_margin = db.Column(db.Float)
    revenue = db.Column(db.Float)
    free_cash_flow = db.Column(db.Float)
    debt_to_equity = db.Column(db.Float)
    return_on_equity = db.Column(db.Float)
    dividend_yield = db.Column(db.Float)
    shares_outstanding = db.Column(db.Float)
    as_of_date = db.Column(db.Date)
    fetched_at = db.Column(db.DateTime, default=datetime.utcnow)
    raw_payload_json = db.Column(db.Text)

    asset = db.relationship('Asset', back_populates='ticker_fundamentals_latest')


class TickerFetchState(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    asset_id = db.Column(db.Integer, db.ForeignKey('asset.id'), nullable=False, unique=True, index=True)
    history_backfilled_at = db.Column(db.DateTime)
    daily_fundamentals_fetched_at = db.Column(db.DateTime)
    intraday_fetched_at = db.Column(db.DateTime)
    last_market_refresh_at = db.Column(db.DateTime)
    last_market_close_trade_date = db.Column(db.Date)
    last_fundamentals_trade_date = db.Column(db.Date)
    last_daily_bar_date = db.Column(db.Date)
    last_intraday_bar_timestamp = db.Column(db.DateTime)
    last_success_at = db.Column(db.DateTime)
    last_attempt_at = db.Column(db.DateTime)
    last_error_at = db.Column(db.DateTime)
    last_error_type = db.Column(db.String(64))
    last_error_message = db.Column(db.Text)
    failure_count = db.Column(db.Integer, default=0)
    next_retry_at = db.Column(db.DateTime)
    priority_requested_at = db.Column(db.DateTime)
    is_backfill_pending = db.Column(db.Boolean, default=True)
    is_fundamentals_pending = db.Column(db.Boolean, default=True)
    is_intraday_pending = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    asset = db.relationship('Asset', back_populates='ticker_fetch_state')


class WorkerLease(db.Model):
    lease_name = db.Column(db.String(100), primary_key=True)
    owner_id = db.Column(db.String(255))
    leased_until = db.Column(db.DateTime)
    heartbeat_at = db.Column(db.DateTime)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ScreenerDefinition(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    name = db.Column(db.String(255), nullable=False)
    description = db.Column(db.Text)
    filters_json = db.Column(db.Text, nullable=False)
    sort_json = db.Column(db.Text)
    is_archived = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard', back_populates='screener_definitions')
    creator = db.relationship('User')

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


class MappingRuleSet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    name = db.Column(db.String(255), nullable=False)
    is_default = db.Column(db.Boolean, default=False, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    user = db.relationship('User')
    entries = db.relationship(
        'MappingRuleEntry',
        back_populates='rule_set',
        cascade='all, delete-orphan',
        order_by='MappingRuleEntry.position.asc()'
    )


class MappingRuleEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    rule_set_id = db.Column(db.Integer, db.ForeignKey('mapping_rule_set.id'), nullable=False, index=True)
    pattern = db.Column(db.String(500), nullable=False)
    category = db.Column(db.String(100), nullable=False)
    position = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    rule_set = db.relationship('MappingRuleSet', back_populates='entries')

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


class CsvAiJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.String(255), unique=True, nullable=False, index=True)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False, index=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False, index=True)
    chat_session_id = db.Column(db.Integer, db.ForeignKey('chat_session.id'), nullable=False, index=True)
    prompt = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(50), default='queued', nullable=False)  # queued, running, completed, failed
    phase = db.Column(db.String(50), default='queued')
    is_filter_request = db.Column(db.Boolean, default=False)
    concurrency = db.Column(db.Integer, default=2)
    batch_size = db.Column(db.Integer, default=40)
    total_rows = db.Column(db.Integer, default=0)
    total_batches = db.Column(db.Integer, default=0)
    completed_batches = db.Column(db.Integer, default=0)
    failed_batches = db.Column(db.Integer, default=0)
    rows_processed = db.Column(db.Integer, default=0)
    rows_removed = db.Column(db.Integer, default=0)
    result_csv_data = db.Column(db.Text)
    explanation = db.Column(db.Text)
    error_message = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard')
    user = db.relationship('User')
    chat_session = db.relationship('ChatSession')
    batches = db.relationship(
        'CsvAiJobBatch',
        back_populates='job',
        order_by='CsvAiJobBatch.batch_index',
        cascade='all, delete-orphan'
    )

    def get_result_csv_data(self):
        return decrypt_str(self.result_csv_data)

    def set_result_csv_data(self, csv_data):
        self.result_csv_data = encrypt_str(csv_data) if csv_data is not None else None


class CsvAiJobBatch(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    job_id = db.Column(db.Integer, db.ForeignKey('csv_ai_job.id'), nullable=False, index=True)
    batch_index = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(50), default='queued', nullable=False)  # queued, running, completed, failed
    input_row_count = db.Column(db.Integer, default=0)
    output_row_count = db.Column(db.Integer, default=0)
    rows_removed = db.Column(db.Integer, default=0)
    error_message = db.Column(db.Text)
    explanation = db.Column(db.Text)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    job = db.relationship('CsvAiJob', back_populates='batches')

    __table_args__ = (
        db.UniqueConstraint('job_id', 'batch_index', name='unique_csv_ai_job_batch'),
    )

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


class AnalyticsSession(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    session_id = db.Column(db.String(255), unique=True, nullable=False)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    conversation_history = db.Column(db.Text)  # JSON of [{role, content, summary, timestamp}]
    status = db.Column(db.String(50), default='active')  # active, cancelled, expired
    expires_at = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    dashboard = db.relationship('Dashboard')
    user = db.relationship('User')

    def get_history(self):
        if self.conversation_history:
            try:
                return json.loads(self.conversation_history)
            except Exception:
                return []
        return []

    def add_entry(self, role, content, summary=None, meta=None):
        history = self.get_history()
        entry = {
            'role': role,
            'content': content,
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat()
        }
        if meta is not None:
            entry['meta'] = meta
        history.append(entry)
        self.conversation_history = json.dumps(history)

class UserDashboardSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    dashboard_id = db.Column(db.Integer, db.ForeignKey('dashboard.id'), nullable=False)
    edit_mode = db.Column(db.String(50), default='private')  # 'private', 'public'
    selected_investing_watchlist_id = db.Column(db.Integer, nullable=True)
    selected_investing_screener_id = db.Column(db.Integer, nullable=True)
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
