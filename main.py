
import os
import uuid
import json
import random
import datetime
import requests
from functools import wraps
from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, g
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from dotenv import load_dotenv

# Load environment variables from a project-local .env file (if present) before
# reading any os.environ below. Existing process env vars take precedence.
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', os.urandom(24).hex())
# Set database URL
database_url = os.environ.get('DATABASE_URL', 'sqlite:///logflow.db')
if database_url.startswith('postgresql'):
    # Add connection timeout parameter with single sslmode setting
    if '?' not in database_url:
        database_url += '?'
    else:
        database_url += '&'
    database_url += 'sslmode=prefer&connect_timeout=10'
    
    # Ensure we don't have conflicting sslmode parameters
    if "sslmode=require" in database_url and "sslmode=prefer" in database_url:
        database_url = database_url.replace("sslmode=require", "")

app.config['SQLALCHEMY_DATABASE_URI'] = database_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SQLALCHEMY_ENGINE_OPTIONS'] = {
    'pool_pre_ping': True,  # Check connection before use
    'pool_recycle': 300,    # Recycle connections every 5 minutes
    'pool_timeout': 30,     # Connection timeout
    'max_overflow': 10      # Allow 10 extra connections when pool is full
}
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)

# Security settings - only secure cookies in production with HTTPS
is_production = os.environ.get('FLASK_ENV') == 'production'
app.config['SESSION_COOKIE_SECURE'] = is_production
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = datetime.timedelta(days=7)

CORS(app)
db = SQLAlchemy(app)

# Setup rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://",
)

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    projects = db.relationship('Project', backref='owner', lazy=True)
    
    def __repr__(self):
        return f'<User {self.username}>'

class Project(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    api_key = db.Column(db.String(64), unique=True, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    logs = db.relationship('Log', backref='project', lazy=True)
    errors = db.relationship('Error', backref='project', lazy=True)
    uptimes = db.relationship('Uptime', backref='project', lazy=True)
    storage_size = db.Column(db.BigInteger, default=0)  # Storage size in bytes
    
    def __repr__(self):
        return f'<Project {self.name}>'
        
    @property
    def storage_size_mb(self):
        """Return storage size in MB"""
        return self.storage_size / (1024 * 1024)
        
    def check_storage_limit(self):
        """Check if project has reached the 500MB storage limit"""
        MAX_STORAGE_BYTES = 500 * 1024 * 1024  # 500MB in bytes
        return self.storage_size >= MAX_STORAGE_BYTES

class Log(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message = db.Column(db.Text, nullable=False)
    level = db.Column(db.String(20), nullable=False, default='INFO')
    source = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    meta_data = db.Column(db.Text, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    
    def __repr__(self):
        return f'<Log {self.level}: {self.message[:30]}>'

class Error(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    error_id = db.Column(db.String(12), unique=True, nullable=False, default=lambda: ''.join(random.choices('ABCDEFGHJKLMNPQRSTUVWXYZ23456789', k=8)))
    message = db.Column(db.Text, nullable=False)
    stack_trace = db.Column(db.Text, nullable=True)
    type = db.Column(db.String(50), nullable=True)
    source = db.Column(db.String(100), nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    meta_data = db.Column(db.Text, nullable=True)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    resolved = db.Column(db.Boolean, default=False)
    
    def __repr__(self):
        return f'<Error {self.error_id} {self.type}: {self.message[:30]}>'

class Uptime(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    endpoint_url = db.Column(db.String(255), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    check_interval = db.Column(db.Integer, default=5)  # minutes
    last_checked = db.Column(db.DateTime, nullable=True)
    last_status = db.Column(db.Boolean, default=False)
    response_time = db.Column(db.Float, nullable=True)  # in milliseconds
    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)
    project_id = db.Column(db.Integer, db.ForeignKey('project.id'), nullable=False)
    
    def __repr__(self):
        return f'<Uptime {self.name}: {self.endpoint_url}>'
        
    def calculate_uptime_percentage(self):
        """Calculate the uptime percentage based on logs in the last 30 days"""
        from sqlalchemy import and_
        
        # If never checked, return 'N/A'
        if not self.last_checked:
            return None
            
        thirty_days_ago = datetime.datetime.utcnow() - datetime.timedelta(days=30)
        
        # Get all logs related to this uptime monitor in the last 30 days
        logs = Log.query.filter(
            and_(
                Log.source == "uptime-monitor",
                Log.project_id == self.project_id,
                Log.timestamp >= thirty_days_ago,
                Log.message.like(f"%{self.name}%")
            )
        ).all()
        
        # Count successful and failed checks
        total_checks = len(logs)
        if total_checks == 0:
            return None
            
        successful_checks = sum(1 for log in logs if "UP" in log.message)
        
        # Calculate percentage
        uptime_percentage = (successful_checks / total_checks) * 100
        return round(uptime_percentage, 2)

# Authentication
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def api_key_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key')
        if not api_key:
            return jsonify({'error': 'API key is required'}), 401
        
        project = Project.query.filter_by(api_key=api_key).first()
        if not project:
            return jsonify({'error': 'Invalid API key'}), 401
        
        g.project = project
        return f(*args, **kwargs)
    return decorated_function

# Routes - Web UI
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/health')
def health_check():
    return jsonify({'status': 'healthy', 'timestamp': datetime.datetime.utcnow().isoformat()}), 200

@app.route('/documentation')
def documentation():
    return render_template('documentation.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        if User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('register'))
        
        if User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('register'))
        
        user = User(
            username=username,
            email=email,
            password_hash=generate_password_hash(password),
            is_admin=False
        )
        
        db.session.add(user)
        db.session.commit()
        
        flash('Registration successful! Please log in.')
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        try:
            user = User.query.filter_by(email=email).first()
            
            if not user or not check_password_hash(user.password_hash, password):
                flash('Invalid email or password')
                return redirect(url_for('login'))
            
            session['user_id'] = user.id
            session['username'] = user.username
            session.permanent = True  # Always keep users logged in
            
            return redirect(url_for('dashboard'))
        except Exception as e:
            app.logger.error(f"Database error during login: {str(e)}")
            flash('A database error occurred. Please try again later.')
            return redirect(url_for('login'))
    
    return render_template('login.html')

@app.route('/account/settings', methods=['GET', 'POST'])
@login_required
def account_settings():
    user = User.query.get(session['user_id'])
    
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        current_password = request.form.get('current_password')
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')
        
        # Check if username already exists (if changed)
        if username != user.username and User.query.filter_by(username=username).first():
            flash('Username already exists')
            return redirect(url_for('account_settings'))
        
        # Check if email already exists (if changed)
        if email != user.email and User.query.filter_by(email=email).first():
            flash('Email already exists')
            return redirect(url_for('account_settings'))
        
        # Update basic info
        user.username = username
        user.email = email
        
        # Update password if provided
        if current_password and new_password and confirm_password:
            if not check_password_hash(user.password_hash, current_password):
                flash('Current password is incorrect')
                return redirect(url_for('account_settings'))
            
            if new_password != confirm_password:
                flash('New passwords do not match')
                return redirect(url_for('account_settings'))
            
            user.password_hash = generate_password_hash(new_password)
            flash('Password updated successfully')
        
        db.session.commit()
        flash('Account settings updated successfully')
        return redirect(url_for('account_settings'))
    
    return render_template('account_settings.html', user=user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    user = User.query.get(session['user_id'])
    projects = Project.query.filter_by(user_id=user.id).all()
    
    # Get aggregate stats for each project
    projects_data = []
    for project in projects:
        log_count = Log.query.filter_by(project_id=project.id).count()
        error_count = Error.query.filter_by(project_id=project.id).count()
        unresolved_errors = Error.query.filter_by(project_id=project.id, resolved=False).count()
        
        # Get recent logs and errors
        recent_logs = Log.query.filter_by(project_id=project.id).order_by(Log.timestamp.desc()).limit(5).all()
        recent_errors = Error.query.filter_by(project_id=project.id).order_by(Error.timestamp.desc()).limit(5).all()
        
        projects_data.append({
            'project': project,
            'log_count': log_count,
            'error_count': error_count,
            'unresolved_errors': unresolved_errors,
            'recent_logs': recent_logs,
            'recent_errors': recent_errors
        })
    
    return render_template('dashboard.html', user=user, projects_data=projects_data)

@app.route('/projects/new', methods=['GET', 'POST'])
@login_required
def new_project():
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        
        # Generate a unique API key
        api_key = str(uuid.uuid4()).replace('-', '')
        
        project = Project(
            name=name,
            description=description,
            api_key=api_key,
            user_id=session['user_id']
        )
        
        db.session.add(project)
        db.session.commit()
        
        flash('Project created successfully!')
        return redirect(url_for('project_details', project_id=project.id))
    
    return render_template('new_project.html')

@app.route('/projects/<int:project_id>')
@login_required
def project_details(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    # Get logs with pagination
    page = request.args.get('page', 1, type=int)
    logs = Log.query.filter_by(project_id=project.id).order_by(Log.timestamp.desc()).paginate(page=page, per_page=50)
    
    # Get error statistics
    error_count = Error.query.filter_by(project_id=project.id).count()
    unresolved_errors = Error.query.filter_by(project_id=project.id, resolved=False).count()
    
    return render_template('project_details.html', 
                           project=project, 
                           logs=logs,
                           error_count=error_count,
                           unresolved_errors=unresolved_errors)

@app.route('/projects/<int:project_id>/errors')
@login_required
def project_errors(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    # Filter by resolved status if specified
    resolved = request.args.get('resolved')
    if resolved == 'true':
        errors_query = Error.query.filter_by(project_id=project.id, resolved=True)
    elif resolved == 'false':
        errors_query = Error.query.filter_by(project_id=project.id, resolved=False)
    else:
        errors_query = Error.query.filter_by(project_id=project.id)
    
    # Get errors with pagination
    page = request.args.get('page', 1, type=int)
    errors = errors_query.order_by(Error.timestamp.desc()).paginate(page=page, per_page=50)
    
    return render_template('project_errors.html', project=project, errors=errors)

@app.route('/projects/<int:project_id>/errors/<int:error_id>')
@login_required
def error_details(project_id, error_id):
    project = Project.query.get_or_404(project_id)
    error = Error.query.get_or_404(error_id)
    
    # Ensure the user owns this project and the error belongs to the project
    if project.user_id != session['user_id'] or error.project_id != project.id:
        flash('You do not have access to this resource')
        return redirect(url_for('dashboard'))
    
    return render_template('error_details.html', project=project, error=error)

@app.route('/projects/<int:project_id>/errors/<int:error_id>/resolve', methods=['POST'])
@login_required
def resolve_error(project_id, error_id):
    project = Project.query.get_or_404(project_id)
    error = Error.query.get_or_404(error_id)
    
    # Ensure the user owns this project and the error belongs to the project
    if project.user_id != session['user_id'] or error.project_id != project.id:
        flash('You do not have access to this resource')
        return redirect(url_for('dashboard'))
    
    error.resolved = True
    db.session.commit()
    
    flash('Error marked as resolved')
    return redirect(url_for('error_details', project_id=project_id, error_id=error_id))

@app.route('/projects/<int:project_id>/errors/resolve-all', methods=['POST'])
@login_required
def resolve_all_errors(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    # Get all unresolved errors and mark them as resolved
    unresolved_errors = Error.query.filter_by(project_id=project.id, resolved=False).all()
    count = len(unresolved_errors)
    
    for error in unresolved_errors:
        error.resolved = True
    
    db.session.commit()
    
    flash(f'{count} errors marked as resolved')
    return redirect(url_for('project_errors', project_id=project_id))

@app.route('/projects/<int:project_id>/settings', methods=['GET', 'POST'])
@login_required
def project_settings(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        description = request.form.get('description', '')
        
        # Update project details
        if name:
            project.name = name
            project.description = description
            db.session.commit()
            flash('Project settings updated successfully!')
            return redirect(url_for('project_settings', project_id=project.id))
        else:
            flash('Project name cannot be empty')
    
    return render_template('project_settings.html', project=project)

@app.route('/projects/<int:project_id>/reset-data', methods=['POST'])
@login_required
def reset_project_data(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete all logs and errors for this project
        Log.query.filter_by(project_id=project.id).delete()
        Error.query.filter_by(project_id=project.id).delete()
        
        # Reset storage size
        project.storage_size = 0
        db.session.commit()
        
        flash('All logs and errors have been deleted successfully!')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}')
    
    return redirect(url_for('project_settings', project_id=project.id))

@app.route('/projects/<int:project_id>/regenerate-key', methods=['POST'])
@login_required
def regenerate_api_key(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    try:
        # Generate a new unique API key
        new_api_key = str(uuid.uuid4()).replace('-', '')
        project.api_key = new_api_key
        db.session.commit()
        
        flash('API key regenerated successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}')
    
    return redirect(url_for('project_settings', project_id=project.id))

@app.route('/projects/<int:project_id>/delete', methods=['POST'])
@login_required
def delete_project(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    try:
        # Delete all associated data
        Log.query.filter_by(project_id=project.id).delete()
        Error.query.filter_by(project_id=project.id).delete()
        Uptime.query.filter_by(project_id=project.id).delete()
        
        # Delete the project
        db.session.delete(project)
        db.session.commit()
        
        flash('Project deleted successfully')
    except Exception as e:
        db.session.rollback()
        flash(f'An error occurred: {str(e)}')
    
    return redirect(url_for('dashboard'))

@app.route('/projects/<int:project_id>/uptime', methods=['GET'])
@login_required
def project_uptime(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    # Get uptime monitors with pagination
    page = request.args.get('page', 1, type=int)
    uptimes = Uptime.query.filter_by(project_id=project.id).paginate(page=page, per_page=10)
    
    # No need to pre-calculate percentages as the method will be called from the template
    
    return render_template('project_uptime.html', project=project, uptimes=uptimes)

@app.route('/projects/<int:project_id>/uptime/new', methods=['GET', 'POST'])
@login_required
def new_uptime(project_id):
    project = Project.query.get_or_404(project_id)
    
    # Ensure the user owns this project
    if project.user_id != session['user_id']:
        flash('You do not have access to this project')
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        name = request.form.get('name')
        endpoint_url = request.form.get('endpoint_url')
        check_interval = request.form.get('check_interval', 5, type=int)
        
        if not name or not endpoint_url:
            flash('Name and endpoint URL are required')
            return redirect(url_for('new_uptime', project_id=project.id))
        
        # Create new uptime monitor
        uptime = Uptime(
            name=name,
            endpoint_url=endpoint_url,
            check_interval=check_interval,
            project_id=project.id
        )
        
        db.session.add(uptime)
        db.session.commit()
        
        flash('Uptime monitor created successfully!')
        return redirect(url_for('project_uptime', project_id=project.id))
    
    return render_template('new_uptime.html', project=project)

@app.route('/projects/<int:project_id>/uptime/<int:uptime_id>/ping', methods=['POST'])
@login_required
def ping_uptime(project_id, uptime_id):
    project = Project.query.get_or_404(project_id)
    uptime = Uptime.query.get_or_404(uptime_id)
    
    # Ensure the user owns this project and the uptime belongs to the project
    if project.user_id != session['user_id'] or uptime.project_id != project.id:
        flash('You do not have access to this resource')
        return redirect(url_for('dashboard'))
    
    # Manually check this uptime monitor
    try:
        import requests
        from datetime import datetime
        
        # Make request to endpoint and measure response time
        start_time = datetime.utcnow()
        response = requests.get(uptime.endpoint_url, timeout=10)
        end_time = datetime.utcnow()
        
        # Calculate response time in milliseconds
        response_time = (end_time - start_time).total_seconds() * 1000
        
        # Update monitor status
        uptime.last_checked = datetime.utcnow()
        uptime.last_status = response.status_code < 400
        uptime.response_time = response_time
        
        # Create a log entry for this check
        status_text = "UP" if uptime.last_status else "DOWN"
        log = Log(
            message=f"Manual uptime check: {uptime.name} is {status_text} (HTTP {response.status_code}, {response_time:.2f}ms)",
            level="INFO" if uptime.last_status else "ERROR",
            source="uptime-monitor",
            project_id=project.id
        )
        db.session.add(log)
        
        # If down, create an error
        if not uptime.last_status:
            error = Error(
                message=f"Endpoint {uptime.name} is DOWN",
                type="UptimeError",
                source="uptime-monitor",
                meta_data=json.dumps({
                    "endpoint": uptime.endpoint_url,
                    "status_code": response.status_code,
                    "response_time": response_time
                }),
                project_id=project.id
            )
            db.session.add(error)
        
        db.session.commit()
        flash(f'Monitor pinged successfully. Status: {status_text}')
    except Exception as e:
        # Handle connection errors
        uptime.last_checked = datetime.utcnow()
        uptime.last_status = False
        uptime.response_time = None
        
        # Log the error
        log = Log(
            message=f"Manual uptime check failed: {uptime.name} - {str(e)}",
            level="ERROR",
            source="uptime-monitor",
            project_id=project.id
        )
        db.session.add(log)
        
        # Create an error
        error = Error(
            message=f"Failed to check endpoint {uptime.name}",
            type="UptimeConnectionError",
            source="uptime-monitor",
            meta_data=json.dumps({
                "endpoint": uptime.endpoint_url,
                "error": str(e)
            }),
            project_id=project.id
        )
        db.session.add(error)
        
        db.session.commit()
        flash(f'Monitor ping failed: {str(e)}')
    
    return redirect(url_for('project_uptime', project_id=project_id))

@app.route('/projects/<int:project_id>/uptime/<int:uptime_id>/delete', methods=['POST'])
@login_required
def delete_uptime(project_id, uptime_id):
    project = Project.query.get_or_404(project_id)
    uptime = Uptime.query.get_or_404(uptime_id)
    
    # Ensure the user owns this project and the uptime belongs to the project
    if project.user_id != session['user_id'] or uptime.project_id != project.id:
        flash('You do not have access to this resource')
        return redirect(url_for('dashboard'))
    
    db.session.delete(uptime)
    db.session.commit()
    
    flash('Uptime monitor deleted successfully')
    return redirect(url_for('project_uptime', project_id=project_id))

# Routes - API
@app.route('/api/logs', methods=['POST'])
@api_key_required
@limiter.limit("60 per minute")
def create_log():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check if project has reached storage limit
    project = g.project
    if project.check_storage_limit():
        # Clear old logs and errors if limit reached
        old_logs = Log.query.filter_by(project_id=project.id).all()
        old_errors = Error.query.filter_by(project_id=project.id).all()
        
        for log in old_logs:
            db.session.delete(log)
        
        for error in old_errors:
            db.session.delete(error)
            
        # Reset storage size
        project.storage_size = 0
        db.session.commit()
    
    # Handle single log
    message = data.get('message', '')
    meta_data = json.dumps(data.get('metadata')) if data.get('metadata') else None
    
    # Calculate storage size for this entry
    log_size = len(message) + (len(meta_data) if meta_data else 0)
    
    log = Log(
        message=message,
        level=data.get('level', 'INFO'),
        source=data.get('source'),
        meta_data=meta_data,
        project_id=project.id
    )
    
    # Update project storage size
    project.storage_size += log_size
    
    db.session.add(log)
    db.session.commit()
    
    return jsonify({'message': 'Log created successfully', 'log_id': log.id}), 201

@app.route('/api/logs/bulk', methods=['POST'])
@api_key_required
@limiter.limit("30 per minute")
def create_bulk_logs():
    data = request.get_json()
    
    if not data or not isinstance(data, list):
        return jsonify({'error': 'Invalid data format. Expected a list of logs'}), 400
    
    # Check if project has reached storage limit
    project = g.project
    if project.check_storage_limit():
        # Clear old logs and errors if limit reached
        old_logs = Log.query.filter_by(project_id=project.id).all()
        old_errors = Error.query.filter_by(project_id=project.id).all()
        
        for log in old_logs:
            db.session.delete(log)
        
        for error in old_errors:
            db.session.delete(error)
            
        # Reset storage size
        project.storage_size = 0
        db.session.commit()
    
    logs = []
    total_size = 0
    
    for log_data in data:
        message = log_data.get('message', '')
        meta_data = json.dumps(log_data.get('metadata')) if log_data.get('metadata') else None
        
        # Calculate storage size for this entry
        log_size = len(message) + (len(meta_data) if meta_data else 0)
        total_size += log_size
        
        log = Log(
            message=message,
            level=log_data.get('level', 'INFO'),
            source=log_data.get('source'),
            meta_data=meta_data,
            project_id=project.id
        )
        logs.append(log)
    
    # Update project storage size
    project.storage_size += total_size
    
    db.session.add_all(logs)
    db.session.commit()
    
    return jsonify({'message': f'Successfully created {len(logs)} logs'}), 201

@app.route('/api/errors', methods=['POST'])
@api_key_required
@limiter.limit("60 per minute")
def create_error():
    data = request.get_json()
    
    if not data:
        return jsonify({'error': 'No data provided'}), 400
    
    # Check if project has reached storage limit
    project = g.project
    if project.check_storage_limit():
        # Clear old logs and errors if limit reached
        old_logs = Log.query.filter_by(project_id=project.id).all()
        old_errors = Error.query.filter_by(project_id=project.id).all()
        
        for log in old_logs:
            db.session.delete(log)
        
        for error in old_errors:
            db.session.delete(error)
            
        # Reset storage size
        project.storage_size = 0
        db.session.commit()
    
    # Calculate storage size for this entry
    message = data.get('message', '')
    stack_trace = data.get('stack_trace', '')
    meta_data = json.dumps(data.get('metadata')) if data.get('metadata') else None
    
    # Calculate storage size
    error_size = len(message) + len(stack_trace) + (len(meta_data) if meta_data else 0)
    
    error = Error(
        message=message,
        stack_trace=stack_trace,
        type=data.get('type'),
        source=data.get('source'),
        meta_data=meta_data,
        project_id=project.id
    )
    
    # Update project storage size
    project.storage_size += error_size
    
    db.session.add(error)
    db.session.commit()
    
    return jsonify({
        'message': 'Error logged successfully', 
        'error_id': error.error_id,
        'id': error.id
    }), 201

@app.route('/api/errors/bulk', methods=['POST'])
@api_key_required
@limiter.limit("30 per minute")
def create_bulk_errors():
    data = request.get_json()
    
    if not data or not isinstance(data, list):
        return jsonify({'error': 'Invalid data format. Expected a list of errors'}), 400
    
    # Check if project has reached storage limit
    project = g.project
    if project.check_storage_limit():
        # Clear old logs and errors if limit reached
        old_logs = Log.query.filter_by(project_id=project.id).all()
        old_errors = Error.query.filter_by(project_id=project.id).all()
        
        for log in old_logs:
            db.session.delete(log)
        
        for error in old_errors:
            db.session.delete(error)
            
        # Reset storage size
        project.storage_size = 0
        db.session.commit()
    
    errors = []
    error_ids = []
    total_size = 0
    
    for error_data in data:
        message = error_data.get('message', '')
        stack_trace = error_data.get('stack_trace', '')
        meta_data = json.dumps(error_data.get('metadata')) if error_data.get('metadata') else None
        
        # Calculate storage size
        error_size = len(message) + len(stack_trace) + (len(meta_data) if meta_data else 0)
        total_size += error_size
        
        error = Error(
            message=message,
            stack_trace=stack_trace,
            type=error_data.get('type'),
            source=error_data.get('source'),
            meta_data=meta_data,
            project_id=g.project.id
        )
        errors.append(error)
    
    # Update project storage size
    project.storage_size += total_size
    
    db.session.add_all(errors)
    db.session.commit()
    
    # Collect all the error IDs
    for error in errors:
        error_ids.append(error.error_id)
    
    return jsonify({
        'message': f'Successfully logged {len(errors)} errors',
        'error_ids': error_ids
    }), 201

# Uptime checker function
def check_uptime():
    """
    Function to check all uptime monitors
    This should be run periodically (e.g., by a scheduler)
    """
    import requests
    from datetime import datetime, timedelta

    with app.app_context():
        # Get monitors that need to be checked (based on check_interval)
        now = datetime.utcnow()
        uptimes = Uptime.query.all()
        
        for uptime in uptimes:
            # Check if it's time to check this monitor
            if uptime.last_checked is None or \
               now >= uptime.last_checked + timedelta(minutes=uptime.check_interval):
                try:
                    # Make request to endpoint and measure response time
                    start_time = datetime.utcnow()
                    response = requests.get(uptime.endpoint_url, timeout=10)
                    end_time = datetime.utcnow()
                    
                    # Calculate response time in milliseconds
                    response_time = (end_time - start_time).total_seconds() * 1000
                    
                    # Update monitor status
                    uptime.last_checked = now
                    uptime.last_status = response.status_code < 400
                    uptime.response_time = response_time
                    
                    # Only create a log entry if the service is DOWN
                    status_text = "UP" if uptime.last_status else "DOWN"
                    
                    # Only log if service is down to prevent excessive logging
                    if not uptime.last_status:
                        log = Log(
                            message=f"Uptime check: {uptime.name} is DOWN (HTTP {response.status_code}, {response_time:.2f}ms)",
                            level="ERROR",
                            source="uptime-monitor",
                            project_id=uptime.project_id
                        )
                        db.session.add(log)
                    
                    # If down, create an error
                    if not uptime.last_status:
                        error = Error(
                            message=f"Endpoint {uptime.name} is DOWN",
                            type="UptimeError",
                            source="uptime-monitor",
                            meta_data=json.dumps({
                                "endpoint": uptime.endpoint_url,
                                "status_code": response.status_code,
                                "response_time": response_time
                            }),
                            project_id=uptime.project_id
                        )
                        db.session.add(error)
                    
                    db.session.commit()
                except Exception as e:
                    # Handle connection errors
                    uptime.last_checked = now
                    uptime.last_status = False
                    uptime.response_time = None
                    
                    # Log the error
                    log = Log(
                        message=f"Uptime check failed: {uptime.name} - {str(e)}",
                        level="ERROR",
                        source="uptime-monitor",
                        project_id=uptime.project_id
                    )
                    db.session.add(log)
                    
                    # Create an error
                    error = Error(
                        message=f"Failed to check endpoint {uptime.name}",
                        type="UptimeConnectionError",
                        source="uptime-monitor",
                        meta_data=json.dumps({
                            "endpoint": uptime.endpoint_url,
                            "error": str(e)
                        }),
                        project_id=uptime.project_id
                    )
                    db.session.add(error)
                    
                    db.session.commit()

# Initialize database
with app.app_context():
    try:
        # Create any missing tables
        db.create_all()
        print("Database tables created successfully")
        
        # For PostgreSQL, use the session to execute ALTER TABLE statement
        try:
            from sqlalchemy import text
            db.session.execute(text('ALTER TABLE project ADD COLUMN IF NOT EXISTS storage_size BIGINT DEFAULT 0'))
            db.session.commit()
            print("Added storage_size column to project table")
        except Exception as e:
            # If error, likely column exists or table doesn't exist yet
            print(f"Error adding column (might already exist): {e}")
            db.session.rollback()
    except Exception as e:
        print(f"Error with database initialization: {e}")

# Setup background thread for uptime checks
import threading
import time

def uptime_checker_thread():
    """Background thread to periodically check uptime monitors"""
    while True:
        try:
            check_uptime()
        except Exception as e:
            print(f"Error in uptime checker: {e}")
        time.sleep(60)  # Check every minute

# Start the uptime checker thread when in production
if os.environ.get('FLASK_ENV') == 'production':
    uptime_thread = threading.Thread(target=uptime_checker_thread, daemon=True)
    uptime_thread.start()

# This block is only for local development
if __name__ == '__main__':
    # Use debug mode only in development
    debug_mode = os.environ.get('FLASK_ENV', 'development') == 'development'
    port = int(os.environ.get('PORT', 5000))
    
    app.run(host="0.0.0.0", port=port, debug=debug_mode)
