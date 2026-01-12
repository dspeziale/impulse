import sys
import os
import psutil
import platform
import socket
import requests
from collections import defaultdict

# Add the project root to sys.path to resolve imports correctly
# This allows running 'python api/index.py' directly from the root
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import smtplib
import secrets
import string
import uuid
import io
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, date, timedelta
from flask import Flask, render_template, jsonify, request, redirect, url_for, flash, send_file
from sqlalchemy import create_engine, text, or_
from sqlalchemy.orm import sessionmaker, scoped_session
from dotenv import load_dotenv
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from api.models import Base, User, UserRole, Log, Message, Notification, Cantiere, Automezzo, AutomezzoType, Timbratura, TimbraturaType, Assenza, Settings
from api.traccar import TraccarClient
import qrcode
from PIL import Image, ImageDraw, ImageFont

load_dotenv()

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Database Configuration
DATABASE_URL = os.getenv('DATABASE_URL')
engine = None
db_session = None
db_error = None

if DATABASE_URL:
    try:
        if DATABASE_URL.startswith("postgres://"):
            DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)
        
        engine = create_engine(
            DATABASE_URL, 
            pool_pre_ping=True, 
            pool_recycle=300,
            connect_args={'sslmode': 'require'}
        )
        # Create tables if they don't exist
        Base.metadata.create_all(engine)
        
        session_factory = sessionmaker(bind=engine)
        db_session = scoped_session(session_factory)
    except Exception as e:
        db_error = str(e)
        print(f"Failed to connect to database: {e}")
else:
    db_error = "DATABASE_URL environment variable not set."

@app.teardown_appcontext
def shutdown_session(exception=None):
    if db_session:
        db_session.remove()

# Flask-Login Configuration
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

@login_manager.user_loader
def load_user(user_id):
    if db_session:
        return db_session.query(User).get(int(user_id))
    return None

def get_settings():
    if not db_session:
        return None
    try:
        settings = db_session.query(Settings).first()
        if not settings:
            # Create default settings from env or defaults
            settings = Settings(
                traccar_url=os.getenv('TRACCAR_URL', "http://demo.traccar.org"),
                traccar_user=os.getenv('TRACCAR_USER'),
                traccar_pass=os.getenv('TRACCAR_PASS'),
                gmail_user=os.getenv('GMAIL_USER'),
                gmail_pass=os.getenv('GMAIL_APP_PASSWORD')
            )
            db_session.add(settings)
            db_session.commit()
        return settings
    except Exception as e:
        print(f"Error fetching settings: {e}")
        return None

def send_email(to_email, subject, body):
    settings = get_settings()
    if not settings or not settings.gmail_user or not settings.gmail_pass:
        print("Email credentials not set.")
        return False
    try:
        msg = MIMEMultipart()
        msg['From'] = settings.gmail_user
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(settings.gmail_user, settings.gmail_pass)
        text_msg = msg.as_string()
        server.sendmail(settings.gmail_user, to_email, text_msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

def generate_temp_password(length=8):
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for i in range(length))

def log_operation(action, details=None, user_id=None, ip_address=None):
    if not db_session:
        return
    try:
        log = Log(
            user_id=user_id,
            action=action,
            details=details,
            ip_address=ip_address
        )
        db_session.add(log)
        db_session.commit()
    except Exception as e:
        print(f"Logging failed: {e}")
        db_session.rollback()

def send_system_notification(user_id, title, message, category="info"):
    """
    Helper to create a notification from backend code.
    """
    if not db_session:
        return False
    try:
        notif = Notification(
            user_id=user_id,
            title=title,
            message=message,
            category=category
        )
        db_session.add(notif)
        db_session.commit()
        return True
    except Exception as e:
        print(f"Notification failed: {e}")
        db_session.rollback()
        return False

def send_system_message(sender_id, recipient_id, subject, body):
    """
    Helper to create a message from backend code.
    Automatically creates a notification for the recipient.
    """
    if not db_session:
        return False
    try:
        msg = Message(
            sender_id=sender_id,
            recipient_id=recipient_id,
            subject=subject,
            body=body
        )
        db_session.add(msg)
        # Auto-notify logic removed to separate Messages vs Notifications
        # Messages will only appear in the Messages dropdown
        # sender = db_session.query(User).get(sender_id)
        # sender_name = f"{sender.nome} {sender.cognome}" if sender else "Unknown"
        # 
        # notif = Notification(
        #     user_id=recipient_id,
        #     title="New Message",
        #     message=f"You have a new message from {sender_name}",
        #     category="info"
        # )
        # db_session.add(notif)
        
        db_session.commit()
        return True
    except Exception as e:
        print(f"Message send failed: {e}")
        db_session.rollback()
        return False

@app.context_processor
def inject_counts():
    if current_user.is_authenticated and db_session:
        try:
             unread_msgs_query = db_session.query(Message).filter_by(recipient_id=current_user.id, read_at=None, deleted_by_recipient=False)
             unread_msgs_count = unread_msgs_query.count()
             
             # Fetch recent messages with sender info (joined query or lazy load)
             # SQLAlchemy lazy loading will handle sender access in template if relationship is defined
             # But Message model needs 'sender' relationship. Let's check api/models.py first?
             # Assuming relationship is set up or we rely on foreign key.
             # Ideally: recent_msgs = unread_msgs_query.order_by(Message.timestamp.desc()).limit(3).all()
             # However, we want ALL recent messages (even read ones maybe? No, typically unread or just latest inbox)
             # Let's show latest INBOX messages regardless of read status, but prioritize unread?
             # AdminLTE usually shows "New Messages". Let's stick to UNREAD for badge, but LATEST for dropdown?
             # Let's show LATEST received messages.
             # Let's show LATEST received messages that are UNREAD.
             recent_msgs = db_session.query(Message).filter_by(recipient_id=current_user.id, read_at=None, deleted_by_recipient=False).order_by(Message.timestamp.desc()).limit(3).all()

             unread_notifs_query = db_session.query(Notification).filter_by(user_id=current_user.id, read_at=None)
             unread_notifs_count = unread_notifs_query.count()
             recent_notifs = unread_notifs_query.order_by(Notification.timestamp.desc()).limit(5).all()
             
             return dict(unread_msgs=unread_msgs_count, unread_notifs=unread_notifs_count, recent_notifs=recent_notifs, recent_msgs=recent_msgs)
        except Exception as e:
             print(f"Error in inject_counts: {e}")
             return dict(unread_msgs=0, unread_notifs=0, recent_notifs=[], recent_msgs=[])
    return dict(unread_msgs=0, unread_notifs=0, recent_notifs=[], recent_msgs=[])

# Routes
@app.route('/')
@login_required
def index():
    if current_user.force_change_password:
        return redirect(url_for('change_password'))
    today_str = datetime.now().strftime('%Y-%m-%d')
    
    # Dashboard Stats
    total_users = 0
    total_cantieri = 0
    total_automezzi = 0
    present_today = 0
    recent_activity = []
    fleet_status = [] # New list for dashboard card
    
    if db_session:
        total_users = db_session.query(User).filter_by(is_active_account=True).count()
        total_cantieri = db_session.query(Cantiere).count()
        total_automezzi = db_session.query(Automezzo).count()
        
        # Calculate distinct users present today
        today_match = f"{today_str}%"
        present_count = db_session.query(Timbratura.user_id).filter(Timbratura.timestamp >= datetime.strptime(today_str, '%Y-%m-%d')).distinct().count()
        present_today = present_count
        
        # Recent Activity (Last 5 stamps)
        recent_activity = db_session.query(Timbratura).order_by(Timbratura.timestamp.desc()).limit(5).all()

        # --- FLEET STATUS LOGIC ---
        print(f"--- DEBUG: Starting Fleet Logic {datetime.now()} ---")
        try:
            # 1. First, populate fleet_status with ALL local vehicles (Default: Offline)
            all_autos = db_session.query(Automezzo).all()
            print(f"--- DEBUG: Local Autos: {len(all_autos)} ---")
            
            # Helper to quickly find entry in list later
            # We build the list initially
            fleet_map = {} 
            
            for auto in all_autos:
                entry = {
                    'id': auto.id,
                    'targa': auto.targa,
                    'name': auto.name,
                    'tipo': auto.tipo if auto.tipo else 'Car',
                    'status': 'offline', # Default
                    'speed': 0,
                    'is_moving': False
                }
                fleet_status.append(entry)
                fleet_map[auto.id] = entry
            
            # 2. Try to enrich with Traccar Data
            try:
                settings = get_settings()
                traccar_client = None
                if settings and settings.traccar_url:
                     traccar_client = TraccarClient(settings.traccar_url, settings.traccar_user, settings.traccar_pass)
                
                if traccar_client and traccar_client.login():
                     print("--- DEBUG: Traccar Login OK ---")
                     devices = traccar_client.get_devices() or []
                     positions = traccar_client.get_positions() or []
                     
                     # Map positions by deviceId
                     pos_map = {p['deviceId']: p for p in positions}
                     
                     # Map Traccar Devices to DB ID or License Plate
                     for auto in all_autos:
                         t_dev = None
                         # Try ID match
                         if auto.id_traccar:
                             t_dev = next((d for d in devices if str(d['id']) == str(auto.id_traccar)), None)
                         
                         # Try Targa match
                         if not t_dev:
                             t_dev = next((d for d in devices if d.get('licensePlate', '').lower() == auto.targa.lower()), None)
                         
                         if t_dev and auto.id in fleet_map:
                             # Update status
                             entry = fleet_map[auto.id]
                             entry['status'] = t_dev.get('status', 'offline')
                             
                             pid = t_dev.get('positionId')
                             if pid and pid in pos_map:
                                 pos = pos_map[pid]
                                 speed = pos.get('speed', 0) # Knots
                                 entry['speed'] = speed
                                 if speed > 1:
                                     entry['is_moving'] = True
                else:
                    print("--- DEBUG: Traccar Login FAILED (Skipping enrichment) ---")
            except Exception as e_traccar:
                print(f"--- DEBUG: Traccar Enrichment Error: {e_traccar}")
                # We continue, so we at least show offline vehicles
            
            # 3. Sort List
            # Sort: Moving first, then Online, then Offline
            def sort_key(x):
                 return (x['is_moving'], x['status'] == 'online')
            
            fleet_status.sort(key=sort_key, reverse=True)

        except Exception as e:
            print(f"--- DEBUG: Critical Dashboard Fleet Error: {e}")
            import traceback
            traceback.print_exc()

    return render_template('index.html', 
                           user=current_user,
                           total_users=total_users,
                           total_cantieri=total_cantieri,
                           total_automezzi=total_automezzi,
                           present_today=present_today,
                           recent_activity=recent_activity,
                           fleet_status=fleet_status)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
        
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        if db_session:
            user = db_session.query(User).filter_by(email=email).first()
            if user and check_password_hash(user.password_hash, password):
                if not user.is_active_account:
                     flash('Account suspended.', 'danger')
                     return redirect(url_for('login'))

                login_user(user, remember=remember)
                log_operation("Login", f"User {user.email} logged in", user.id, request.remote_addr)
                return redirect(url_for('index'))
        
        flash('Invalid email or password', 'danger')
        
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    log_operation("Logout", f"User {current_user.email} logged out", current_user.id, request.remote_addr)
    logout_user()
    return redirect(url_for('login'))

@app.route('/change-password', methods=['GET', 'POST'])
@login_required
def change_password():
    if not current_user.force_change_password:
        return redirect(url_for('index'))

    if request.method == 'POST':
        new_password = request.form.get('new_password')
        confirm_password = request.form.get('confirm_password')

        if new_password != confirm_password:
            flash('Passwords do not match', 'danger')
        elif len(new_password) < 6:
            flash('Password must be at least 6 characters', 'danger')
        else:
            current_user.password_hash = generate_password_hash(new_password)
            current_user.force_change_password = False
            db_session.commit()
            flash('Password changed successfully', 'success')
            return redirect(url_for('index'))
            
    return render_template('change_password.html')

# USER CRUD API (For Admin/Supervisor)
# NOTE: In a real app, protect these with @login_required and role checks

@app.route('/users', methods=['GET'])
@login_required
def list_users():
    return render_template('users_list.html')

@app.route('/api/users/dt', methods=['POST'])
@login_required
def users_dt():
    if not db_session:
        return jsonify({"error": "DB not connected"}), 500
        
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search_value = request.form.get('search[value]')
    
    # Ordering
    order_column = request.form.get('order[0][column]', type=int)
    order_dir = request.form.get('order[0][dir]')
    
    query = db_session.query(User)
    
    # Search Filter
    if search_value:
        search = f"%{search_value}%"
        query = query.filter(or_(
            User.nome.ilike(search),
            User.cognome.ilike(search),
            User.email.ilike(search)
        ))
        
    total_filtered = query.count()
    
    # Sorting
    if order_column is not None:
        # Map DataTables column index to model field
        # 0: id, 1: photo, 2: name, 3: email, 4: role, 5: status, 6: action
        order_col_name = None
        if order_column == 0:
            order_col_name = User.id
        elif order_column == 2:
            order_col_name = User.nome # Sort by First Name for simplicity, or combine
        elif order_column == 3:
            order_col_name = User.email
        elif order_column == 4:
            order_col_name = User.role
            
        if order_col_name:
            if order_dir == 'desc':
                query = query.order_by(order_col_name.desc())
            else:
                query = query.order_by(order_col_name.asc())
            
    # Pagination
    if start is not None and length is not None:
        query = query.offset(start).limit(length)
        
    data = []
    for user in query.all():
        data.append({
            "id": user.id,
            "photo_url": user.photo_url,
            "name": f"{user.nome} {user.cognome}",
            "nome": user.nome, # Send raw data for edit modal
            "cognome": user.cognome,
            "email": user.email,
            "role": user.role.value,
            "role_raw": user.role.name,
            "status": "Active" if user.is_active_account else "Suspended",
            "is_active": user.is_active_account
        })
        
    return jsonify({
        "draw": draw,
        "recordsTotal": db_session.query(User).count(),
        "recordsFiltered": total_filtered,
        "data": data
    })

# --- Messaging & Notifications Routes ---

@app.route('/messages', methods=['GET'])
@login_required
def messages_view():
    if not db_session:
        return "DB Error", 500
    
    users = db_session.query(User).filter(User.id != current_user.id).all()
    received = db_session.query(Message).filter_by(recipient_id=current_user.id, deleted_by_recipient=False).order_by(Message.timestamp.desc()).all()
    sent = db_session.query(Message).filter_by(sender_id=current_user.id, deleted_by_sender=False).order_by(Message.timestamp.desc()).all()
    
    return render_template('messages.html', received=received, sent=sent, users=users)

@app.route('/messages/send', methods=['POST'])
@login_required
def send_message():
    recipient_id = request.form.get('recipient_id')
    subject = request.form.get('subject')
    body = request.form.get('body')
    
    success = send_system_message(current_user.id, recipient_id, subject, body)
    
    if success:
        log_operation("Message Sent", f"To User {recipient_id}", current_user.id, request.remote_addr)
        flash('Message sent successfully', 'success')
    else:
        flash('Failed to send message', 'danger')
        
    return redirect(url_for('messages_view'))

@app.route('/messages/read/<int:message_id>', methods=['POST'])
@login_required
def read_message(message_id):
    if db_session:
        msg = db_session.query(Message).filter_by(id=message_id, recipient_id=current_user.id).first()
        if msg:
            msg.read_at = datetime.utcnow()
            db_session.commit()
            return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/notifications/read/<int:notif_id>', methods=['POST'])
@login_required
def read_notification(notif_id):
    if db_session:
        notif = db_session.query(Notification).filter_by(id=notif_id, user_id=current_user.id).first()
        if notif:
            notif.read_at = datetime.utcnow()
            db_session.commit()
            return jsonify({'success': True})
    return jsonify({'success': False}), 400

@app.route('/admin/logs', methods=['GET'])
@login_required
def view_logs():
    # Role Check
    if current_user.role.name not in ['ADMINISTRATOR', 'SUPERVISOR']:
        flash('Access Denied', 'danger')
        return redirect(url_for('index'))
        
    if db_session:
        # Simple limit for now, ideally pagination like Users
        logs = db_session.query(Log).order_by(Log.timestamp.desc()).limit(100).all()
        return render_template('logs.html', logs=logs)
    return "DB Error", 500

@app.route('/admin/logs/prune', methods=['POST'])
@login_required
def prune_logs():
    # Role Check
    if current_user.role.name not in ['ADMINISTRATOR', 'SUPERVISOR']:
        flash('Access Denied', 'danger')
        return redirect(url_for('view_logs'))

    days_str = request.form.get('days')
    if not days_str or not days_str.isdigit():
        flash('Invalid days value', 'danger')
        return redirect(url_for('view_logs'))
    
    days = int(days_str)
    cutoff_date = datetime.now() - timedelta(days=days)
    
    if db_session:
        try:
            # Using SQLAlchemy delete
            deleted_count = db_session.query(Log).filter(Log.timestamp < cutoff_date).delete()
            db_session.commit()
            
            # Log this operation (it won't be deleted as it's new)
            log_operation("Logs Pruned", f"Deleted {deleted_count} logs older than {days} days", current_user.id, request.remote_addr)
            flash(f'Successfully deleted {deleted_count} logs older than {days} days.', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Error pruning logs: {str(e)}', 'danger')
    
    return redirect(url_for('view_logs'))



# ... imports ...

# Route to serve user photo
import io
from flask import send_file

@app.route('/users/photo/<int:user_id>')
def user_photo(user_id):
    if not db_session:
        return "DB Error", 500
    user = db_session.query(User).get(user_id)
    if user and user.photo_data:
        return send_file(
            io.BytesIO(user.photo_data),
            mimetype='image/jpeg',
            as_attachment=False,
            download_name=f"user_{user_id}.jpg"
        )
    # Return default avatar if no photo
    return redirect("https://cdn.jsdelivr.net/npm/admin-lte@3.2/dist/img/avatar5.png")

@app.route('/users/create', methods=['POST'])
@login_required
def create_user():
    # Only Admins should create users (add check here)
    nome = request.form.get('nome')
    cognome = request.form.get('cognome')
    email = request.form.get('email')
    role = request.form.get('role') # Enum string
    
    # Generate Temp Password
    temp_password = generate_temp_password()
    password_hash = generate_password_hash(temp_password)
    
    # Photo Upload (BLOB)
    photo_data = None
    role = request.form.get('role')
    
    # Check if email exists
    existing = db_session.query(User).filter_by(email=email).first()
    if existing:
        flash("Email already exists", "danger")
        return redirect(url_for('list_users'))

    # Generate temporary password
    temp_password = f"Impulse{uuid.uuid4().hex[:4]}!"
    
    try:
        new_user = User(
            nome=nome,
            cognome=cognome, # Added cognome
            email=email,
            password_hash=generate_password_hash(temp_password),
            role=UserRole[role.upper()] if role else UserRole.USER, # Adjusted to use UserRole enum
            force_change_password=True # Adjusted to match original User model attribute
        )
        
        # Handle Photo Upload
        if 'photo' in request.files:
            file = request.files['photo']
            if file and file.filename != '':
                file_data = file.read()
                new_user.photo_data = file_data

        db_session.add(new_user)
        db_session.commit()
        
        # Update photo_url now that we have ID
        if new_user.photo_data: # Only set if photo data was provided
            new_user.photo_url = url_for('user_photo', user_id=new_user.id, _external=True) # Added _external=True
            db_session.commit()

        # Send Email
        email_body = f"Hello {nome},\n\nYour account has been created.\nLogin: {email}\nTemporary Password: {temp_password}\n\nPlease change it on first login."
        send_email(email, "Welcome to Impulse App", email_body)
        
        log_operation("User Created", f"Created user {email} ({role})", current_user.id, request.remote_addr)

    except Exception as e:
        db_session.rollback()
        flash(f"Error creating user: {str(e)}", "danger")
        return redirect(url_for('list_users'))

    flash(f'User created successfully. Temp Password: {temp_password}', 'success')
    return redirect(url_for('list_users'))

@app.route('/users/update/<int:user_id>', methods=['POST'])
@login_required
def update_user(user_id):
    if not db_session: return "DB Error", 500
    user = db_session.query(User).get(user_id)
    if not user:
        flash('User not found', 'danger')
        return redirect(url_for('list_users'))
        
    user.nome = request.form.get('nome') # Changed from 'name' to 'nome'
    user.cognome = request.form.get('cognome') # Added cognome
    user.email = request.form.get('email')
    user.role = UserRole[request.form.get('role').upper()] # Adjusted to use UserRole enum
    
    # Handle Photo
    if 'photo' in request.files:
        file = request.files['photo']
        if file and file.filename != '':
             user.photo_data = file.read()
             user.photo_url = url_for('user_photo', user_id=user.id, _external=True) # Added _external=True
    
    try:
        db_session.commit()
        log_operation("User Updated", f"Updated user {user.email}", current_user.id, request.remote_addr)
        flash('User updated successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error: {str(e)}', 'danger')
        
    return redirect(url_for('list_users'))

@app.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
def delete_user(user_id):
    if not db_session: return "DB Error", 500
    user = db_session.query(User).get(user_id)
    if user:
        try:
            email = user.email
            db_session.delete(user)
            db_session.commit()
            log_operation("User Deleted", f"Deleted user {email}", current_user.id, request.remote_addr)
            flash('User deleted', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Error: {str(e)}', 'danger')
    return redirect(url_for('list_users'))

@app.route('/users/toggle-status/<int:user_id>', methods=['POST'])
@login_required
def toggle_user_status(user_id):
    if not db_session: return "DB Error", 500
    user = db_session.query(User).get(user_id)
    if user:
        user.is_active_account = not user.is_active_account
        db_session.commit()
        action = "Activated" if user.is_active_account else "Deactivated"
        log_operation("User Status Change", f"{action} user {user.email}", current_user.id, request.remote_addr)
        flash(f'User {"activated" if user.is_active_account else "suspended"}', 'info')
    return redirect(url_for('list_users'))

# --- CANTIERI ROUTES ---

@app.route('/cantieri', methods=['GET'])
@login_required
def list_cantieri():
    return render_template('cantieri_list.html')

@app.route('/api/cantieri/dt', methods=['POST'])
@login_required
def cantieri_dt():
    if not db_session:
        return jsonify({"error": "DB not connected"}), 500
        
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search_value = request.form.get('search[value]')
    
    query = db_session.query(Cantiere)
    
    if search_value:
        search = f"%{search_value}%"
        query = query.filter(or_(
            Cantiere.nome.ilike(search),
            Cantiere.citta.ilike(search),
            Cantiere.indirizzo.ilike(search)
        ))
        
    total_filtered = query.count()
    
    # Simple sort by ID desc for now
    query = query.order_by(Cantiere.id.desc())
            
    if start is not None and length is not None:
        query = query.offset(start).limit(length)
        
    data = []
    for c in query.all():
        data.append({
            "id": c.id,
            "nome": c.nome,
            "citta": c.citta,
            "indirizzo": c.indirizzo,
            "stato": c.stato,
            "gps": c.coordinate_gps
        })
        
    return jsonify({
        "draw": draw,
        "recordsTotal": db_session.query(Cantiere).count(),
        "recordsFiltered": total_filtered,
        "data": data
    })

@app.route('/cantieri/create', methods=['POST'])
@login_required
def create_cantiere():
    if not db_session: return "DB Error", 500
    
    nome = request.form.get('nome')
    citta = request.form.get('citta')
    indirizzo = request.form.get('indirizzo')
    gps = request.form.get('coordinate_gps')
    start = request.form.get('orario_lavoro_inizio')
    end = request.form.get('orario_lavoro_fine')
    
    # Unique QR Code string (using UUID or simple ID based)
    # Using a UUID to be safe and unique
    qr_code = f"CANTIERE-{uuid.uuid4().hex[:8].upper()}"
    
    new_cantiere = Cantiere(
        nome=nome,
        citta=citta,
        indirizzo=indirizzo,
        coordinate_gps=gps,
        orario_lavoro_inizio=start,
        orario_lavoro_fine=end,
        qr_code_univoco=qr_code
    )
    
    try:
        db_session.add(new_cantiere)
        db_session.commit()
        log_operation("Cantiere Created", f"Created cantiere {nome}", current_user.id, request.remote_addr)
        flash('Cantiere created successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error: {str(e)}', 'danger')
        
    return redirect(url_for('list_cantieri'))

@app.route('/cantieri/qr/<int:cantiere_id>')
def cantiere_qr(cantiere_id):
    if not db_session: return "DB Error", 500
    c = db_session.query(Cantiere).get(cantiere_id)
    if not c: return "Not Found", 404
    
    # Generate QR Code
    qr = qrcode.QRCode(version=1, box_size=10, border=4)
    # Data is the unique code or JSON? Simple code for now.
    qr.add_data(c.qr_code_univoco) 
    qr.make(fit=True)
    img_qr = qr.make_image(fill_color="black", back_color="white").convert('RGB')
    
    # Create a canvas to add text
    # Canvas size: QR width, QR height + padding for text
    width, height = img_qr.size
    canvas_height = height + 100 # 50px top, 50px bottom
    canvas = Image.new('RGB', (width, canvas_height), 'white')
    
    # Paste QR in middle
    canvas.paste(img_qr, (0, 50))
    
    draw = ImageDraw.Draw(canvas)
    
    # Load font (default or custom if available)
    try:
        font = ImageFont.truetype("arial.ttf", 20)
    except:
        font = ImageFont.load_default()
        
    # Draw Name (Top)
    # Ideally center text. Simple implementation:
    draw.text((10, 10), f"Cantiere: {c.nome}", fill="black", font=font)
    
    # Draw Address (Bottom)
    draw.text((10, height + 60), f"{c.indirizzo}, {c.citta}", fill="black", font=font)
    
    # Return image
    img_io = io.BytesIO()
    canvas.save(img_io, 'PNG')
    img_io.seek(0)
    
    return send_file(img_io, mimetype='image/png', as_attachment=False, download_name=f"qr_{c.id}.png")

@app.route('/cantieri/update/<int:id>', methods=['POST'])
@login_required
def update_cantiere(id):
    if not db_session: return "DB Error", 500
    cantiere = db_session.query(Cantiere).get(id)
    if not cantiere:
        flash('Cantiere not found', 'danger')
        return redirect(url_for('list_cantieri'))
        
    try:
        cantiere.nome = request.form.get('nome')
        cantiere.citta = request.form.get('citta')
        cantiere.indirizzo = request.form.get('indirizzo')
        
        gps = request.form.get('coordinate_gps')
        if gps:
            parts = gps.split(',')
            if len(parts) == 2:
                cantiere.latitudine = float(parts[0])
                cantiere.longitudine = float(parts[1])
        
        # Optional Hours
        start = request.form.get('orario_lavoro_inizio')
        end = request.form.get('orario_lavoro_fine')
        if start: cantiere.orario_lavoro_inizio = datetime.strptime(start, '%H:%M').time()
        if end: cantiere.orario_lavoro_fine = datetime.strptime(end, '%H:%M').time()
        
        db_session.commit()
        log_operation("Cantiere Updated", f"Updated cantiere {cantiere.nome}", current_user.id, request.remote_addr)
        flash('Cantiere updated successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error updating cantiere: {str(e)}', 'danger')
        
    return redirect(url_for('list_cantieri'))

@app.route('/cantieri/delete/<int:id>', methods=['POST'])
@login_required
def delete_cantiere(id):
    if not db_session: return "DB Error", 500
    if current_user.role.value != 'ADMINISTRATOR': # Protect critical deletes
        flash('Unauthorized', 'danger')
        return redirect(url_for('list_cantieri'))
        
    item = db_session.query(Cantiere).get(id)
    if item:
        try:
            name = item.nome
            db_session.delete(item)
            db_session.commit()
            log_operation("Cantiere Deleted", f"Deleted cantiere {name}", current_user.id, request.remote_addr)
            flash('Cantiere eliminato con successo', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Errore: {str(e)}', 'danger')
            
    return redirect(url_for('list_cantieri'))

# --- AUTOMEZZI ROUTES ---

@app.route('/automezzi', methods=['GET'])
@login_required
def list_automezzi():
    return render_template('automezzi_list.html')

@app.route('/api/automezzi/dt', methods=['POST'])
@login_required
def automezzi_dt():
    if not db_session:
        return jsonify({"error": "DB not connected"}), 500
        
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search_value = request.form.get('search[value]')
    
    query = db_session.query(Automezzo)
    
    if search_value:
        search = f"%{search_value}%"
        query = query.filter(or_(
            Automezzo.targa.ilike(search),
            Automezzo.id_traccar.ilike(search)
        ))
        
    total_filtered = query.count()
    query = query.order_by(Automezzo.id.desc())
            
    if start is not None and length is not None:
        query = query.offset(start).limit(length)
        
    data = []
    for a in query.all():
        data.append({
            "id": a.id,
            "tipo": a.tipo.value, # Enum value
            "targa": a.targa,
            "stato": a.stato,
            "id_traccar": a.id_traccar
        })
        
    return jsonify({
        "draw": draw,
        "recordsTotal": db_session.query(Automezzo).count(),
        "recordsFiltered": total_filtered,
        "data": data
    })

@app.route('/automezzi/create', methods=['POST'])
@login_required
def create_automezzo():
    if not db_session: return "DB Error", 500
    
    tipo = request.form.get('tipo')
    targa = request.form.get('targa')
    stato = request.form.get('stato')
    id_traccar = request.form.get('id_traccar')
    
    from api.models import AutomezzoType
    
    new_automezzo = Automezzo(
        tipo=AutomezzoType[tipo], # Enum lookup
        targa=targa,
        stato=stato,
        id_traccar=id_traccar
    )
    
    try:
        db_session.add(new_automezzo)
        db_session.commit()
        log_operation("Automezzo Created", f"Created automezzo {targa}", current_user.id, request.remote_addr)
        flash('Automezzo created successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error: {str(e)}', 'danger')
        
    return redirect(url_for('list_automezzi'))

@app.route('/automezzi/update/<int:id>', methods=['POST'])
@login_required
def update_automezzo(id):
    if not db_session: return "DB Error", 500
    auto = db_session.query(Automezzo).get(id)
    if not auto:
        flash('Automezzo not found', 'danger')
        return redirect(url_for('list_automezzi'))

    try:
        auto.tipo = request.form.get('tipo', 'CAR')
        auto.targa = request.form.get('targa')
        auto.stato = request.form.get('stato')
        
        traccar_id = request.form.get('id_traccar')
        if traccar_id and traccar_id.strip():
            auto.id_traccar = int(traccar_id)
        else:
            auto.id_traccar = None
            
        db_session.commit()
        log_operation("Automezzo Updated", f"Updated vehicle {auto.targa}", current_user.id, request.remote_addr)
        flash('Automezzo updated successfully', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Error updating automezzo: {str(e)}', 'danger')

    return redirect(url_for('list_automezzi'))

@app.route('/automezzi/delete/<int:id>', methods=['POST'])
@login_required
def delete_automezzo(id):
    if not db_session: return "DB Error", 500
    if current_user.role.value != 'ADMINISTRATOR':
        flash('Unauthorized', 'danger')
        return redirect(url_for('list_automezzi'))

    item = db_session.query(Automezzo).get(id)
    if item:
        try:
            targa = item.targa
            db_session.delete(item)
            db_session.commit()
            log_operation("Automezzo Deleted", f"Deleted automezzo {targa}", current_user.id, request.remote_addr)
            flash('Automezzo eliminato con successo', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Errore: {str(e)}', 'danger')
            
    return redirect(url_for('list_automezzi'))

# --- TIMBRATURE ROUTES ---

import math
from datetime import datetime, date

def calculate_distance(lat1, lon1, lat2, lon2):
    # Haversine formula
    R = 6371000 # Radius of Earth in meters
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    
    a = math.sin(delta_phi / 2.0) ** 2 + \
        math.cos(phi1) * math.cos(phi2) * \
        math.sin(delta_lambda / 2.0) ** 2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
    
    return R * c

@app.route('/timbrature', methods=['GET'])
@login_required
def list_timbrature():
    return render_template('timbrature_list.html')

@app.route('/api/timbrature/dt', methods=['POST'])
@login_required
def timbrature_dt():
    if not db_session: return jsonify({"error": "DB Error"}), 500
    
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search_value = request.form.get('search[value]')
    
    query = db_session.query(Timbratura).join(User).join(Cantiere)
    
    # Filter Logic
    is_admin = current_user.role.name == 'ADMINISTRATOR'
    show_all = request.form.get('show_all') == 'true'
    
    if not is_admin or not show_all:
        query = query.filter(Timbratura.user_id == current_user.id)
        
    if search_value:
        search = f"%{search_value}%"
        query = query.filter(or_(
            User.nome.ilike(search),
            User.cognome.ilike(search),
            Cantiere.nome.ilike(search)
        ))
        
    total_filtered = query.count()
    query = query.order_by(Timbratura.timestamp.desc())
    
    if start is not None and length is not None:
        query = query.offset(start).limit(length)
        
    data = []
    for t in query.all():
        # Calculate distance if GPS available (optional display)
        dist_str = "N/A"
        # We could recalc distance here if we wanted, or just skip
        
        data.append({
            "timestamp": t.timestamp.strftime('%Y-%m-%d %H:%M:%S'),
            "utente": f"{t.user.nome} {t.user.cognome}",
            "cantiere": t.cantiere.nome,
            "tipo": t.tipo.value,
            "distanza": "Validata" if t.distanza_validata else "Non Validata"
        })
        
    return jsonify({
        "draw": draw,
        "recordsTotal": db_session.query(Timbratura).count(),
        "recordsFiltered": total_filtered,
        "data": data
    })

@app.route('/mobile/scan')
@login_required
def mobile_scan():
    return render_template('timbratura_mobile.html')

@app.route('/api/timbratura', methods=['POST'])
@login_required
def api_timbratura():
    if not db_session: return jsonify({'success': False, 'message': 'DB Error'}), 500
    
    qr_code = request.form.get('qr_code')
    user_lat = request.form.get('lat')
    user_lon = request.form.get('lon')
    force_gps = request.form.get('force_gps') == 'true'
    notes = request.form.get('notes')
    
    if not qr_code or not user_lat or not user_lon:
        return jsonify({'success': False, 'message': 'Missing Data'}), 400
        
    # 1. Find Cantiere
    cantiere = db_session.query(Cantiere).filter_by(qr_code_univoco=qr_code).first()
    if not cantiere:
        return jsonify({'success': False, 'message': 'Invalid QR Code'}), 404
        
    # 2. Validate GPS Distance (Skip if forced with notes)
    cantiere_lat, cantiere_lon = 0.0, 0.0
    distanza_validata = False
    
    try:
        if cantiere.coordinate_gps:
            parts = cantiere.coordinate_gps.split(',')
            cantiere_lat = float(parts[0].strip())
            cantiere_lon = float(parts[1].strip())
            
            dist = calculate_distance(float(user_lat), float(user_lon), cantiere_lat, cantiere_lon)
            # Tolerance: 500 meters
            if dist <= 500:
                distanza_validata = True
            elif not force_gps:
                 return jsonify({'success': False, 'message': f'Too far ({int(dist)}m). Limit 500m.', 'distance': int(dist), 'is_far': True}), 400
            else:
                # Forced because far
                if not notes:
                     return jsonify({'success': False, 'message': 'Notes required for manual override.'}), 400
                     
        else:
             # Cantiere has no GPS set
             if not force_gps:
                return jsonify({'success': False, 'message': 'Cantiere has no GPS. Manual override required.', 'is_far': True}), 400
            
    except ValueError:
        return jsonify({'success': False, 'message': 'Invalid GPS Data'}), 400
        
    # 3. Determine IN/OUT
    today_start = datetime.combine(date.today(), datetime.min.time())
    today_end = datetime.combine(date.today(), datetime.max.time())
    
    # Get stamps for this user & cantiere TODAY
    stamps = db_session.query(Timbratura).filter(
        Timbratura.user_id == current_user.id,
        Timbratura.cantiere_id == cantiere.id,
        Timbratura.timestamp >= today_start,
        Timbratura.timestamp <= today_end
    ).order_by(Timbratura.timestamp.asc()).all()
    
    tipo_timbratura = "ENTRATA"
    from api.models import TimbraturaType
    
    if stamps:
        last_stamp = stamps[-1]
        if last_stamp.tipo == TimbraturaType.ENTRATA:
            tipo_timbratura = "USCITA"
        else:
             tipo_timbratura = "ENTRATA"
             
    # Create Timbratura
    new_stamp = Timbratura(
        user_id=current_user.id,
        cantiere_id=cantiere.id,
        tipo=TimbraturaType[tipo_timbratura],
        coordinate_gps=f"{user_lat},{user_lon}",
        distanza_validata=distanza_validata,
        qr_code_utilizzato=qr_code,
        note=notes
    )
    
    try:
        db_session.add(new_stamp)
        db_session.commit()
        
        # Log it
        log_operation("Timbratura", f"{tipo_timbratura} @ {cantiere.nome}", current_user.id, request.remote_addr)
        
        return jsonify({'success': True, 'message': f'Timbratura {tipo_timbratura} completata!'})
    except Exception as e:
        db_session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/presenze')
@login_required
def list_presenze():
    return render_template('presenze_giornaliere.html')

@app.route('/api/presenze/dt')
@login_required
def api_presenze_dt():
    try:
        # Fetch Data
        query = db_session.query(Timbratura).join(User).order_by(Timbratura.timestamp.asc())
        
        # Check params
        show_all = request.args.get('show_all') == 'true'

        if current_user.role == UserRole.ADMINISTRATOR:
            if not show_all:
                query = query.filter(Timbratura.user_id == current_user.id)
        else:
            query = query.filter(Timbratura.user_id == current_user.id)
            
        all_stamps = query.all()
        print(f"DEBUG PRESENZE: Found {len(all_stamps)} stamps for User {current_user.id} (Role: {current_user.role}, ShowAll: {show_all})")
        
        # Process Data
        # Group by (User, Date)
        daily_data = {}
        
        # Structure: key=(user_id, date_str) val={user_name, date, in, out, notes}
        
        for s in all_stamps:
            try:
                d_str = s.timestamp.strftime('%Y-%m-%d')
                key = (s.user_id, d_str)
                
                if key not in daily_data:
                    daily_data[key] = {
                        'user': f"{s.user.nome} {s.user.cognome}",
                        'date': d_str,
                        'in': None,
                        'out': None, 
                        'notes': []
                    }
                    
                entry = daily_data[key]
                t_str = s.timestamp.strftime('%H:%M')
                
                # Robust extraction of string value
                tipo_val = s.tipo
                if hasattr(tipo_val, 'value'):
                    tipo_val = tipo_val.value
                tipo_str = str(tipo_val).upper()
                
                if "ENTRATA" in tipo_str:
                    if entry['in'] is None:
                        entry['in'] = t_str
                elif "USCITA" in tipo_str:
                    entry['out'] = t_str
                    
                if s.note:
                    entry['notes'].append(s.note)
            except Exception as loop_err:
                print(f"Skipping stamp {s.id} due to error: {loop_err}")
                continue
                
        # Calculate Hours and Format List
        result = []
        for k, v in daily_data.items():
            hours_str = "-"
            if v['in'] and v['out']:
                try:
                    fmt = '%H:%M'
                    t1 = datetime.strptime(v['in'], fmt)
                    t2 = datetime.strptime(v['out'], fmt)
                    diff = t2 - t1
                    total_seconds = diff.total_seconds()
                    hours = int(total_seconds // 3600)
                    minutes = int((total_seconds % 3600) // 60)
                    hours_str = f"{hours}h {minutes}m"
                except:
                    pass
            
            result.append({
                'date': v['date'],
                'user': v['user'],
                'in': v['in'] if v['in'] else "-",
                'out': v['out'] if v['out'] else "-",
                'hours': hours_str,
                'notes': ", ".join(list(set(v['notes'])))
            })
            
        return jsonify({'data': result})
    except Exception as e:
        db_session.rollback()
        import traceback
        error_details = traceback.format_exc()
        # Log to DB instead of file
        try:
             log_operation("API Error", f"Presenze DT: {str(e)}", current_user.id if current_user else 0, request.remote_addr)
        except:
             print("Failed to log to DB")
             
        print(f"Error in api_presenze_dt: {error_details}")
        return jsonify({'error': str(e)}), 500

# --- ASSENZE ROUTES ---

@app.route('/assenze', methods=['GET'])
@login_required
def list_assenze():
    return render_template('assenze_list.html')

@app.route('/api/assenze/dt', methods=['POST'])
@login_required
def assenze_dt():
    if not db_session: return jsonify({"error": "DB Error"}), 500
    
    draw = request.form.get('draw', type=int)
    start = request.form.get('start', type=int)
    length = request.form.get('length', type=int)
    search_value = request.form.get('search[value]')
    
    query = db_session.query(Assenza).join(User)
    
    # If not Admin, show only own absences
    if current_user.role.value != 'ADMINISTRATOR': 
        query = query.filter(Assenza.user_id == current_user.id)
    
    if search_value:
        search = f"%{search_value}%"
        # Search by User Name or Type
        query = query.filter(or_(
            User.nome.ilike(search),
            User.cognome.ilike(search),
            # Assenza.tipo is Enum, casting might be needed for some DBs, or simple check
        ))
        
    total_filtered = query.count()
    query = query.order_by(Assenza.data_inizio.desc())
    
    if start is not None and length is not None:
        query = query.offset(start).limit(length)
        
    data = []
    for a in query.all():
        data.append({
            "id": a.id,
            "utente": f"{a.user.nome} {a.user.cognome}",
            "tipo": a.tipo.value,
            "data_inizio": a.data_inizio.strftime('%Y-%m-%d'),
            "data_fine": a.data_fine.strftime('%Y-%m-%d'),
            "stato": a.stato_approvazione
        })
        
    return jsonify({
        "draw": draw,
        "recordsTotal": db_session.query(Assenza).count(), # This count might need adjustment if filtering by user
        "recordsFiltered": total_filtered,
        "data": data
    })

@app.route('/assenze/create', methods=['POST'])
@login_required
def create_assenza():
    if not db_session: return "DB Error", 500
    
    tipo = request.form.get('tipo')
    start_str = request.form.get('data_inizio')
    end_str = request.form.get('data_fine')
    note = request.form.get('note')
    
    from api.models import AssenzaType
    
    start_date = datetime.strptime(start_str, '%Y-%m-%d')
    end_date = datetime.strptime(end_str, '%Y-%m-%d')
    
    new_assenza = Assenza(
        user_id=current_user.id,
        tipo=AssenzaType[tipo],
        data_inizio=start_date,
        data_fine=end_date,
        note=note,
        stato_approvazione="In Attesa"
    )
    
    try:
        db_session.add(new_assenza)
        db_session.commit()
        
        # Notify Admins (Optional but good)
        log_operation("Richiesta Assenza", f"{tipo} dal {start_str} al {end_str}", current_user.id, request.remote_addr)
        
        flash('Richiesta inviata con successo', 'success')
    except Exception as e:
        db_session.rollback()
        flash(f'Errore: {str(e)}', 'danger')
        
    return redirect(url_for('list_assenze'))

@app.route('/assenze/delete/<int:id>', methods=['POST'])
@login_required
def delete_assenza(id):
    if not db_session: return "DB Error", 500
    
    item = db_session.query(Assenza).get(id)
    if item:
        # Check permission: Admin can delete all, User can delete only their own
        if current_user.role.value != 'ADMINISTRATOR' and item.user_id != current_user.id:
             flash('Unauthorized', 'danger')
             return redirect(url_for('list_assenze'))
             
        try:
            db_session.delete(item)
            db_session.commit()
            log_operation("Assenza Deleted", f"Deleted assenza {id}", current_user.id, request.remote_addr)
            flash('Assenza eliminata con successo', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Errore: {str(e)}', 'danger')
            
    return redirect(url_for('list_assenze'))

@app.route('/assenze/status/<int:assenza_id>', methods=['POST'])
@login_required
def update_assenza_status(assenza_id):
    if not db_session: return jsonify({'success': False}), 500
    if current_user.role.value != 'ADMINISTRATOR': # Changed from 'Admin' to 'ADMINISTRATOR' to match enum
        return jsonify({'success': False, 'message': 'Unauthorized'}), 403
        
    status = request.form.get('status')
    if status not in ['Approvata', 'Rifiutata']:
        return jsonify({'success': False, 'message': 'Invalid Status'}), 400
        
    assenza = db_session.query(Assenza).get(assenza_id)
    if not assenza:
        return jsonify({'success': False, 'message': 'Not Found'}), 404
        
    assenza.stato_approvazione = status
    db_session.commit()
    
    log_operation("Assenza Status Update", f"Assenza {assenza.id} status changed to {status}", current_user.id, request.remote_addr)
    
    # Notify User
    send_system_notification(
        assenza.user_id, 
        f"Assenza {status}", 
        f"La tua richiesta di assenza è stata {status.lower()}.", 
        "success" if status == 'Approvata' else 'danger'
    )
    
    return jsonify({'success': True})

@app.route('/seed-admin')
def seed_admin():
    if not db_session:
        return f"DB Error: {db_error}" if db_error else "DB Error: Unknown"
    
    try:
        existing_admin = db_session.query(User).filter_by(email="admin@impulse.com").first()
        if existing_admin:
            return "Admin already exists."
            
        temp_password = "admin" # Simple for first login
        admin = User(
            nome="Admin",
            cognome="User",
            email="admin@impulse.com",
            password_hash=generate_password_hash(temp_password),
            role=UserRole.ADMINISTRATOR,
            force_change_password=True # Requires change
        )
        db_session.add(admin)
        db_session.commit()
        return f"Admin created. Email: admin@impulse.com, Password: {temp_password}"
    except Exception as e:
        return f"Error during seed: {str(e)}"


@app.route('/api/system-info', methods=['GET'])
@login_required
def get_system_info():
    try:
        cpu_percent = psutil.cpu_percent(interval=1)
        cpu_freq = psutil.cpu_freq()
        memory = psutil.virtual_memory()
        disk = psutil.disk_usage('/')
        boot_time = datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S")
        
        info = {
            "cpu": {
                "percent": cpu_percent,
                "cores_physical": psutil.cpu_count(logical=False),
                "cores_logical": psutil.cpu_count(logical=True),
                "freq_current": f"{cpu_freq.current:.0f} MHz" if cpu_freq else "N/A",
                "freq_max": f"{cpu_freq.max:.0f} MHz" if cpu_freq else "N/A"
            },
            "memory": {
                "total": f"{memory.total / (1024**3):.2f} GB",
                "available": f"{memory.available / (1024**3):.2f} GB",
                "using_percent": memory.percent, 
                "percent": memory.percent
            },
            "disk": {
                "total": f"{disk.total / (1024**3):.2f} GB",
                "free": f"{disk.free / (1024**3):.2f} GB",
                "percent": disk.percent
            },
            "network": {
                 "hostname": socket.gethostname(),
                 "ip": socket.gethostbyname(socket.gethostname()) 
            },
            "os": {
                "system": platform.system(),
                "release": platform.release(),
                "version": platform.version(),
                "machine": platform.machine(),
                "processor": platform.processor(),
                "boot_time": boot_time
            },
            "python_version": platform.python_version()
        }
        return jsonify(info)
    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    print(app.url_map)
    app.run(debug=True)
# --- TRACCAR INTEGRATION ---
from api.traccar import TraccarClient
TRACCAR_URL = os.getenv('TRACCAR_URL')
TRACCAR_USER = os.getenv('TRACCAR_USER')
TRACCAR_PASS = os.getenv('TRACCAR_PASS')

traccar_client = TraccarClient(TRACCAR_URL, TRACCAR_USER, TRACCAR_PASS)

@app.route('/tracking/live')
@login_required
def tracking_live():
    return render_template('tracking_live.html')

@app.route('/api/tracking/sync', methods=['POST'])
@login_required
def sync_traccar():
    """Sync Automezzi with Traccar Devices"""
    print("DEBUG: Starting Traccar Sync")
    try:
        if current_user.role != UserRole.ADMINISTRATOR:
            return jsonify({'error': 'Unauthorized'}), 403
            
        print("DEBUG: Fetching devices...")
        devices = traccar_client.get_devices()
        print(f"DEBUG: Devices fetched: {len(devices) if devices else 'None'}")
        
        updated_count = 0
        created_count = 0
        
        if not devices:
             print("DEBUG: No devices returned")
             return jsonify({'error': 'Failed to fetch devices from Traccar'}), 500

        for dev in devices:
            targa = dev.get('name') 
            dev_id = str(dev.get('id'))
            
            auto = db_session.query(Automezzo).filter_by(id_traccar=dev_id).first()
            if not auto:
                auto = db_session.query(Automezzo).filter_by(targa=targa).first()
                
            if auto:
                if auto.id_traccar != dev_id:
                    auto.id_traccar = dev_id
                    updated_count += 1
            else:
                new_auto = Automezzo(
                    tipo=AutomezzoType.FURGONE, 
                    targa=targa,
                    id_traccar=dev_id,
                    stato="Operativo"
                )
                db_session.add(new_auto)
                created_count += 1
                
        db_session.commit()
        log_operation("Traccar Sync", f"Updated {updated_count}, Created {created_count}", current_user.id, request.remote_addr)
        return jsonify({'status': 'success', 'updated': updated_count, 'created': created_count})
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"DEBUG: Sync Exception: {e}")
        db_session.rollback()
        return jsonify({'error': str(e)}), 500

@app.route('/api/tracking/live_data', methods=['GET'])
@login_required
def tracking_live_data():
    """Get live positions for all synced vehicles"""
    positions = traccar_client.get_positions()
    devices = traccar_client.get_devices()
    
    # Map devices
    dev_map = {d['id']: d for d in devices}
    
    # Filter only synced vehicles
    synced_autos = db_session.query(Automezzo).filter(Automezzo.id_traccar != None).all()
    synced_ids = [int(a.id_traccar) for a in synced_autos if a.id_traccar and a.id_traccar.isdigit()]
    
    result = []
    for pos in positions:
        dev_id = pos.get('deviceId')
        if dev_id in synced_ids:
            device_info = dev_map.get(dev_id, {})
            # Find DB info
            auto = next((a for a in synced_autos if str(a.id_traccar) == str(dev_id)), None)
            
            result.append({
                'id': dev_id,
                'name': device_info.get('name', 'Unknown'),
                'targa': auto.targa if auto else 'Unknown',
                'tipo': auto.tipo.name if auto else 'FURGONE',
                'lat': pos.get('latitude'),
                'lon': pos.get('longitude'),
                'speed': pos.get('speed'), # knots usually, convert to kmh * 1.852 on frontend or here
                'address': pos.get('address'),
                'last_update': pos.get('deviceTime'),
                'icon_type': auto.tipo.name.lower() if auto else 'car',
                'traccar_status': device_info.get('status'), # online, offline, unknown
                'db_stato': auto.stato if auto else 'Unknown'
            })
            
    return jsonify(result)

@app.route('/api/tracking/history', methods=['GET'])
@login_required
def tracking_history():
    device_id = request.args.get('deviceId')
    start = request.args.get('from') # ISO string
    end = request.args.get('to')   # ISO string
    
    if not device_id or not start or not end:
        return jsonify({'error': 'Missing params'}), 400
        
    data = traccar_client.get_route(device_id, start, end)
    return jsonify(data)

@app.route('/api/weather', methods=['GET'])
@login_required
def proxy_weather():
    lat = request.args.get('lat')
    lon = request.args.get('lon')
    if not lat or not lon:
         return jsonify({'error': 'Missing coords'}), 400
         
    # Using Open-Meteo (Free, No Key)
    try:
        print(f"DEBUG: Weather Proxy for Lat={lat} Lon={lon}")
        url = f"https://api.open-meteo.com/v1/forecast?latitude={lat}&longitude={lon}&current_weather=true"
        print(f"DEBUG: Requesting {url}")
        
        r = requests.get(url, timeout=5)
        print(f"DEBUG: Weather Status: {r.status_code}")
        
        if r.status_code != 200:
            print(f"DEBUG: Weather Error Body: {r.text}")
            
        return jsonify(r.json())
    except Exception as e:
        import traceback
        traceback.print_exc()
        print(f"DEBUG: Weather Exception: {e}")
        return jsonify({'error': str(e)}), 500

# --- SETTINGS ROUTES ---

@app.route('/settings/general', methods=['GET', 'POST'])
@login_required
def general_settings():
    # Only Admin/Supervisor
    if current_user.role.name not in ['ADMINISTRATOR', 'SUPERVISOR']:
        flash('Access Denied', 'danger')
        return redirect(url_for('index'))
    
    settings = get_settings()
    if not settings:
         # Should prevent null reference if DB error
         flash('Settings not available', 'danger')
         return redirect(url_for('index'))

    if request.method == 'POST':
        try:
            settings.traccar_url = request.form.get('traccar_url')
            settings.traccar_user = request.form.get('traccar_user')
            settings.traccar_pass = request.form.get('traccar_pass')
            settings.gmail_user = request.form.get('gmail_user')
            settings.gmail_pass = request.form.get('gmail_pass')
            
            # Handle empty strings for ints
            su = request.form.get('speed_limit_urban')
            sex = request.form.get('speed_limit_extra_urban')
            sh = request.form.get('speed_limit_highway')
            
            settings.speed_limit_urban = int(su) if su else 50
            settings.speed_limit_extra_urban = int(sex) if sex else 90
            settings.speed_limit_highway = int(sh) if sh else 130
            
            db_session.commit()
            log_operation("Settings Updated", "General settings updated", current_user.id, request.remote_addr)
            flash('Settings updated successfully', 'success')
        except Exception as e:
            db_session.rollback()
            flash(f'Error updating settings: {str(e)}', 'danger')
            
    return render_template('settings.html', settings=settings)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host='0.0.0.0', port=port)
