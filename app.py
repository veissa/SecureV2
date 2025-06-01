from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import uuid
from cryptography.hazmat.primitives import serialization, hashes, padding
from cryptography.hazmat.primitives.asymmetric import rsa, padding as asymmetric_padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
import hmac
import hashlib
import random
import mimetypes
from utils import generate_rsa_keys, save_rsa_keys, generate_hmac, generate_random_iv, encrypt_with_aes, encrypt_with_rsa, decrypt_with_rsa, decrypt_with_aes, sign_message, verify_signature, verify_hmac,get_user_private_key, get_user_public_key
import requests
import zipfile
import io
import re
import magic
import requests as pyrequests

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = f"sqlite:///{os.path.join(BASE_DIR, 'cloud.db')}"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# Ensure upload folder exists
if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    is_admin = db.Column(db.Boolean, default=False)
    storage_limit = db.Column(db.BigInteger, default=5 * 1024 * 1024 * 1024)  # 5GB default
    last_login = db.Column(db.DateTime)
    files = db.relationship('File', backref='owner', lazy=True)
    folders = db.relationship('Folder', backref='owner', lazy=True)
    groups = db.relationship('Group', secondary='user_groups', backref=db.backref('users', lazy='dynamic'))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='folder', lazy=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]))
    size_limit = db.Column(db.BigInteger)
    group = db.relationship('Group', backref='folders')

class File(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    filename = db.Column(db.String(255), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    mime_type = db.Column(db.String(128))
    folder_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_starred = db.Column(db.Boolean, default=False)
    status = db.Column(db.String(20), nullable=False, default='complete')

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    encrypted_content = db.Column(db.Text, nullable=False)  # Message chiffré avec AES
    encrypted_aes_key = db.Column(db.Text, nullable=False)  # Clé AES chiffrée avec RSA
    encrypted_hmac_key = db.Column(db.Text, nullable=False)  # Clé HMAC chiffrée avec RSA
    iv = db.Column(db.Text, nullable=False)  # Vecteur d'initialisation pour AES
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    signature = db.Column(db.Text, nullable=False)  # Signature du message
    hmac = db.Column(db.Text, nullable=False)  # HMAC pour vérifier l'intégrité
    original_content = db.Column(db.Text)  # Message original pour l'expéditeur
    is_deleted_for_receiver = db.Column(db.Boolean, default=False)  # Indique si le message est supprimé pour le destinataire
    
    sender = db.relationship('User', foreign_keys=[sender_id], backref='sent_messages')
    receiver = db.relationship('User', foreign_keys=[receiver_id], backref='received_messages')

# Table d'association pour la relation many-to-many entre User et Group
user_groups = db.Table('user_groups',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    description = db.Column(db.String(200))
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Announcement(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    to_all = db.Column(db.Boolean, default=False)
    groups = db.relationship('Group', secondary='announcement_groups', backref=db.backref('announcements', lazy='dynamic'))
    author = db.relationship('User', backref='announcements')

# Table d'association entre Announcement et Group
announcement_groups = db.Table('announcement_groups',
    db.Column('announcement_id', db.Integer, db.ForeignKey('announcement.id'), primary_key=True),
    db.Column('group_id', db.Integer, db.ForeignKey('group.id'), primary_key=True)
)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('user_dashboard'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = 'remember' in request.form
        recaptcha_response = request.form.get('g-recaptcha-response')
        # Verify reCAPTCHA
        if not recaptcha_response:
            flash('Please complete the reCAPTCHA.', 'error')
            return render_template('login.html')
        recaptcha_secret = '6LeIxAcTAAAAAGG-vFI1TnRWxMZNFuojJ4WifJWe'
        verify_url = 'https://www.google.com/recaptcha/api/siteverify'
        payload = {'secret': recaptcha_secret, 'response': recaptcha_response, 'remoteip': request.remote_addr}
        r = requests.post(verify_url, data=payload)
        result = r.json()
        if not result.get('success'):
            flash('Invalid reCAPTCHA. Please try again.', 'error')
            return render_template('login.html')
        # Check if user is in waiting period
        last_attempt_time = session.get('last_attempt_time')
        if last_attempt_time:
            wait_time = session.get('wait_time', 0)
            if datetime.utcnow() - datetime.fromisoformat(last_attempt_time) < timedelta(seconds=wait_time):
                remaining_time = int((datetime.fromisoformat(last_attempt_time) + timedelta(seconds=wait_time) - datetime.utcnow()).total_seconds())
                flash(f'Please wait {remaining_time} seconds before trying again.', 'error')
                return render_template('login.html', wait_time=remaining_time)

        # Store credentials for verification after captcha
        session['pending_email'] = email
        session['pending_password'] = password
        session['pending_remember'] = remember

        # Generate captcha question
        a, b = random.randint(1, 9), random.randint(1, 9)
        session['captcha_question'] = f"What is {a} + {b} ?"
        session['captcha_answer'] = str(a + b)
        return redirect(url_for('captcha'))

    return render_template('login.html')

@app.route('/captcha', methods=['GET', 'POST'])
def captcha():
    if 'pending_email' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        answer = request.form.get('captcha_answer', '').strip()
        if answer == session.get('captcha_answer'):
            # Correct captcha, verify credentials
            email = session['pending_email']
            password = session['pending_password']
            remember = session['pending_remember']
            user = User.query.filter_by(email=email).first()

            if user and user.check_password(password):
                # Correct credentials, log in user
                user.last_login = datetime.utcnow()
                db.session.commit()
                login_user(user, remember=remember, duration=timedelta(days=30) if remember else None)
                
                # Clean up session
                session.pop('pending_email', None)
                session.pop('pending_password', None)
                session.pop('pending_remember', None)
                session.pop('captcha_question', None)
                session.pop('captcha_answer', None)
                session.pop('failed_attempts', None)
                session.pop('last_attempt_time', None)
                session.pop('wait_time', None)

                if user.is_admin:
                    return redirect(url_for('admin_dashboard'))
                return redirect(url_for('user_dashboard'))
            else:
                # Incorrect credentials
                failed_attempts = session.get('failed_attempts', 0) + 1
                session['failed_attempts'] = failed_attempts

                if failed_attempts >= 3:
                    # Calculate exponential wait time (5s, 10s, 20s, etc., max 300s)
                    wait_time = min(5 * (2 ** (failed_attempts - 3)), 300)
                    session['wait_time'] = wait_time
                    session['last_attempt_time'] = datetime.utcnow().isoformat()
                    
                    # Clean up session
                    session.pop('pending_email', None)
                    session.pop('pending_password', None)
                    session.pop('pending_remember', None)
                    session.pop('captcha_question', None)
                    session.pop('captcha_answer', None)
                    session.pop('failed_attempts', None)
                    
                    flash(f'Too many failed attempts. Please wait {wait_time} seconds.', 'error')
                    return redirect(url_for('login'))

                # Clean up session and redirect to login page
                session.pop('pending_email', None)
                session.pop('pending_password', None)
                session.pop('pending_remember', None)
                session.pop('captcha_question', None)
                session.pop('captcha_answer', None)
                
                flash(f'Invalid email or password. Remaining attempts: {3 - failed_attempts}', 'error')
                return redirect(url_for('login'))
        else:
            # Incorrect captcha
            error = "Incorrect captcha. Please try again."
            # Generate new question
            a, b = random.randint(1, 9), random.randint(1, 9)
            session['captcha_question'] = f"What is {a} + {b} ?"
            session['captcha_answer'] = str(a + b)
            return render_template('captcha.html', question=session['captcha_question'], error=error)

    # GET request - display captcha form
    question = session.get('captcha_question', 'Error generating captcha.')
    return render_template('captcha.html', question=question)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('You do not have access to this page.', 'error')
        return render_template('user_dashboard.html')
    return render_template('dashboard_admin.html')

@app.route('/user/dashboard')
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('user_dashboard.html')

@app.route('/browse')
@app.route('/browse/<int:folder_id>')
@login_required
def browse(folder_id=None):
    try:
        # Get current folder and its subfolders
        current_folder = None
        subfolders = []
        files = []
        available_folders = []
        root_folder = None
        
        if folder_id:
            # If a specific folder is requested
            if current_user.is_admin:
                # Admins can access all folders
                current_folder = Folder.query.get_or_404(folder_id)
                subfolders = Folder.query.filter_by(parent_id=folder_id).all()
                files = File.query.filter_by(folder_id=folder_id).all()
            else:
                # Normal users can only access their folders and group folders
                current_folder = Folder.query.filter(
                    (Folder.id == folder_id) & 
                    ((Folder.owner_id == current_user.id) | 
                     (Folder.group_id.in_([g.id for g in current_user.groups])))
                ).first_or_404()
                
                subfolders = Folder.query.filter(
                    (Folder.parent_id == folder_id) & 
                    ((Folder.owner_id == current_user.id) | 
                     (Folder.group_id.in_([g.id for g in current_user.groups])))
                ).all()
                
                files = File.query.filter_by(folder_id=folder_id).all()
        else:
            # If no folder is selected
            if current_user.is_admin:
                # Admins see all root folders and the root folder
                root_folder = Folder.query.filter_by(name='root', parent_id=None).first()
                if not root_folder:
                    # Create root folder if it doesn't exist
                    root_folder = Folder(name='root', owner_id=current_user.id)
                    db.session.add(root_folder)
                    db.session.commit()
                available_folders = Folder.query.filter(Folder.parent_id.is_(None), Folder.id != root_folder.id).all()
            else:
                # Normal users only see their root folders and group folders
                available_folders = Folder.query.filter(
                    (Folder.parent_id.is_(None)) & 
                    ((Folder.owner_id == current_user.id) | 
                     (Folder.group_id.in_([g.id for g in current_user.groups])))
                ).all()
        
        # Get current folder path
        folder_path = []
        if current_folder:
            folder = current_folder
            while folder:
                folder_path.insert(0, folder)
                folder = folder.parent
        
        return render_template('browse.html', 
                             current_folder=current_folder,
                             subfolders=subfolders,
                             files=files,
                             folder_path=folder_path,
                             available_folders=available_folders,
                             root_folder=root_folder)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('browse.html', 
                             current_folder=None,
                             subfolders=[],
                             files=[],
                             folder_path=[],
                             available_folders=[],
                             root_folder=None)

@app.route('/upload')
@login_required
def upload():
    try:
        if current_user.is_admin:
            # Admins can see all folders
            folders = Folder.query.all()
        else:
            # Regular users can only see their own folders and group folders they belong to
            user_folders = Folder.query.filter_by(owner_id=current_user.id).all()
            group_folders = Folder.query.filter(Folder.group_id.in_([g.id for g in current_user.groups])).all() if current_user.groups else []
            folders = user_folders + group_folders

        # Get in-progress and completed uploads
        try:
            uploads_in_progress = File.query.filter_by(owner_id=current_user.id, status='in_progress').all()
            completed_uploads = File.query.filter_by(owner_id=current_user.id, status='complete').limit(5).all()
        except:
            uploads_in_progress = []
            completed_uploads = File.query.filter_by(owner_id=current_user.id).limit(5).all()

        # Calculate storage usage
        used_storage = sum(f.size for f in current_user.files)
        total_storage = current_user.storage_limit
        storage_percentage = round((used_storage / total_storage) * 100) if total_storage > 0 else 0

        # Format for display
        if used_storage < 1024**2:
            used_storage_formatted = f"{used_storage/1024:.1f} KB"
        elif used_storage < 1024**3:
            used_storage_formatted = f"{used_storage/(1024**2):.1f} MB"
        else:
            used_storage_formatted = f"{used_storage/(1024**3):.1f} GB"

        if total_storage < 1024**3:
            total_storage_formatted = f"{total_storage/(1024**2):.1f} MB"
        else:
            total_storage_formatted = f"{total_storage/(1024**3):.1f} GB"

        # Media files (all images and videos for the user, from all folders)
        media_files = File.query.filter(
            File.owner_id == current_user.id,
            File.status == 'complete',
            (File.mime_type.like('image/%') | File.mime_type.like('video/%'))
        ).order_by(File.created_at.desc()).all()

        # Recent files (most recently uploaded files for the user, from all folders)
        recent_files = File.query.filter(
            File.owner_id == current_user.id,
            File.status == 'complete'
        ).order_by(File.created_at.desc()).limit(10).all()

        return render_template('upload.html',
                             folders=folders,
                             uploads_in_progress=uploads_in_progress,
                             completed_uploads=completed_uploads,
                             media_files=media_files,
                             recent_files=recent_files,
                             used_storage=used_storage_formatted,
                             total_storage=total_storage_formatted,
                             storage_percentage=storage_percentage)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('upload.html',
                             folders=[],
                             uploads_in_progress=[],
                             completed_uploads=[],
                             media_files=[],
                             recent_files=[],
                             used_storage="0 B",
                             total_storage="0 B",
                             storage_percentage=0)

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'files[]' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})

    # Security settings
    ALLOWED_EXTENSIONS = {'pdf', 'png', 'jpg', 'jpeg', 'gif', 'doc', 'docx', 'xls', 'xlsx', 'txt'}
    ALLOWED_MIME = {
        'pdf': 'application/pdf',
        'png': 'image/png',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'gif': 'image/gif',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'txt': 'text/plain',
    }
    MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB
    VIRUSTOTAL_API_KEY = '134e44c0dab3892634f100559ebfed57bbe8d03c57cdab3b9f3f100af03a2e03'
    VIRUSTOTAL_URL = 'https://www.virustotal.com/api/v3/files/'

    files = request.files.getlist('files[]')
    folder_id = request.form.get('folder_id', type=int)
    folder = None
    
    if folder_id:
        folder = Folder.query.get_or_404(folder_id)
        if not current_user.is_admin:
            # Check if folder is user's own
            if folder.owner_id != current_user.id:
                # Check if folder is a group folder and user is in that group
                if not folder.group_id or not any(g.id == folder.group_id for g in current_user.groups):
                    return jsonify({'success': False, 'message': 'Access denied'}), 403

    used_storage = sum(f.size for f in current_user.files)
    
    uploaded_files = []
    for file in files:
        if file.filename == '':
            continue
            
        # Extension check
        ext = file.filename.rsplit('.', 1)[-1].lower()
        if ext not in ALLOWED_EXTENSIONS:
            return jsonify({'success': False, 'message': f'File type .{ext} not allowed.'}), 400
        
        # Size check
        file.seek(0, 2)
        file_size = file.tell()
        file.seek(0)
        if file_size > MAX_FILE_SIZE:
            return jsonify({'success': False, 'message': f'File too large (max 10MB).'}), 400
        if used_storage + file_size > current_user.storage_limit:
            return jsonify({'success': False, 'message': 'Storage limit exceeded'})
            
        # Magic bytes check
        magic_bytes = file.read(2048)
        file.seek(0)
        mime = magic.from_buffer(magic_bytes, mime=True)
        if ext in ALLOWED_MIME and not mime.startswith(ALLOWED_MIME[ext].split(';')[0]):
            return jsonify({'success': False, 'message': f'File content does not match extension: {mime}'}), 400
        
        # VirusTotal hash lookup
        file_hash = hashlib.sha256(file.read()).hexdigest()
        file.seek(0)
        headers = {'x-apikey': VIRUSTOTAL_API_KEY}
        vt_resp = pyrequests.get(VIRUSTOTAL_URL + file_hash, headers=headers)
        if vt_resp.status_code == 200:
            vt_json = vt_resp.json()
            stats = vt_json.get('data', {}).get('attributes', {}).get('last_analysis_stats', {})
            if stats.get('malicious', 0) > 0 or stats.get('suspicious', 0) > 0:
                return jsonify({'success': False, 'message': 'File flagged as malicious by VirusTotal.'}), 400
        
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
            new_file = File(
                name=filename,
                filename=unique_filename,
                size=file_size,
                mime_type=get_mime_type(filename),
                folder_id=folder_id,
                owner_id=current_user.id,
                status='complete'
            )
            db.session.add(new_file)
            db.session.commit()
            uploaded_files.append(new_file)
            used_storage += file_size
        except Exception as e:
            return jsonify({'success': False, 'message': str(e)})

    try:
        return jsonify({
            'success': True,
            'message': f"Successfully uploaded {len(uploaded_files)} files",
            'files': [{
                'id': f.id,
                'name': f.name,
                'size': f.size,
                'status': 'complete'
            } for f in uploaded_files]
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})
    
@app.route('/api/files/status', methods=['GET'])
@login_required
def get_upload_status():
    try:
        uploads = File.query.filter_by(owner_id=current_user.id).order_by(File.created_at.desc()).limit(10).all()
        
        return jsonify({
            'success': True,
            'uploads': [{
                'id': f.id,
                'name': f.name,
                'size': f.size,
                'status': getattr(f, 'status', 'complete'),  # Use getattr to safely get status
                'progress': 100 if getattr(f, 'status', 'complete') == 'complete' else 70
            } for f in uploads]
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/files/<int:file_id>', methods=['DELETE'])
@login_required
def delete_file(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        if file.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Accès refusé'}), 403

        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        
        # Vérifier si le fichier existe
        if not os.path.exists(file_path):
            print(f"Le fichier n'existe pas: {file_path}")
            # Supprimer quand même l'entrée de la base de données
            db.session.delete(file)
            db.session.commit()
            return jsonify({'success': True, 'message': 'Fichier supprimé de la base de données'})

        try:
            # Supprimer le fichier physique
            os.remove(file_path)
            print(f"Fichier supprimé avec succès: {file_path}")
        except Exception as e:
            print(f"Erreur lors de la suppression du fichier: {str(e)}")
            return jsonify({'success': False, 'message': f'Erreur lors de la suppression du fichier: {str(e)}'}), 500

        # Supprimer l'entrée de la base de données
        db.session.delete(file)
        db.session.commit()
        print(f"Entrée supprimée de la base de données pour le fichier ID: {file_id}")
        
        return jsonify({'success': True, 'message': 'Fichier supprimé avec succès'})
    except Exception as e:
        print(f"Erreur générale lors de la suppression: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': f'Erreur lors de la suppression: {str(e)}'}), 500

@app.route('/api/files/<int:file_id>/cancel', methods=['POST'])
@login_required
def cancel_upload(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
        if os.path.exists(file_path):
            os.remove(file_path)
        
        db.session.delete(file)
        db.session.commit()
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>/pause', methods=['POST'])
@login_required
def pause_upload(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        if file.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        try:
            file.status = 'paused'
            db.session.commit()
            return jsonify({'success': True})
        except:
            # If status column doesn't exist, still return success
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/files/<int:file_id>/resume', methods=['POST'])
@login_required
def resume_upload(file_id):
    try:
        file = File.query.get_or_404(file_id)
        
        if file.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'}), 403

        try:
            file.status = 'in_progress'
            db.session.commit()
            return jsonify({'success': True})
        except:
            # If status column doesn't exist, still return success
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/folders', methods=['POST'])
@login_required
def create_folder():
    try:
        data = request.get_json()
        name = data.get('name')
        parent_id = data.get('parent_id')
        size_limit = data.get('size_limit')
        is_group_folder = data.get('is_group_folder', False)
        group_name = data.get('group_name')
        group_emails = data.get('group_emails', '')
        group_id = None
        if is_group_folder and group_name:
            group = Group.query.filter_by(name=group_name).first()
            if not group:
                group = Group(name=group_name)
                db.session.add(group)
                db.session.flush()  # get group.id
            # Add users by email
            emails = [e.strip() for e in group_emails.split(',') if e.strip()]
            for email in emails:
                user = User.query.filter_by(email=email).first()
                if user and user not in group.users:
                    group.users.append(user)
            if current_user not in group.users:
                group.users.append(current_user)
            db.session.flush()
            group_id = group.id
        # Check if parent folder exists
        if parent_id is not None and parent_id != "null":
            parent = Folder.query.get_or_404(parent_id)
            if parent.owner_id != current_user.id and not current_user.is_admin:
                return jsonify({'success': False, 'message': 'Access denied'})
        new_folder = Folder(
            name=name,
            parent_id=parent_id if parent_id not in [None, "null"] else None,
            owner_id=current_user.id if not is_group_folder else None,
            group_id=group_id,
            size_limit=size_limit if current_user.is_admin else None
        )
        db.session.add(new_folder)
        db.session.commit()
        return jsonify({
            'success': True,
            'message': 'Folder created successfully',
            'folder': {
                'id': new_folder.id,
                'name': new_folder.name,
                'size_limit': new_folder.size_limit
            }
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    # Vérifier si l'utilisateur a accès au fichier
    if not current_user.is_admin and file.owner_id != current_user.id:
        flash('You do not have permission to download this file.', 'error')
        return redirect(url_for('browse'))
    
    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], file.filename),
        as_attachment=True,
        download_name=file.name
    )

@app.route('/view_file/<int:file_id>')
@login_required
def view_file(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.owner_id != current_user.id:
        flash('You do not have permission to view this file.', 'error')
        return redirect(url_for('browse'))

    file_ext = os.path.splitext(file.name)[1].lower()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    mime_type = file.mime_type or 'application/octet-stream'

    # Affichage pour les fichiers texte
    ALLOWED_TEXT_EXTENSIONS = {
        '.txt', '.html', '.css', '.js', '.json', '.xml', '.csv', '.md', '.yaml', '.yml', '.ini', '.cfg',
    }
    if file_ext in ALLOWED_TEXT_EXTENSIONS:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        syntax_modes = {
            '.py': 'python', '.html': 'html', '.css': 'css', '.js': 'javascript', '.json': 'json', '.xml': 'xml', '.md': 'markdown', '.yaml': 'yaml', '.yml': 'yaml'
        }
        syntax_mode = syntax_modes.get(file_ext, 'plaintext')
        return render_template('view_text.html', filename=file.name, content=content, file_id=file_id, syntax_mode=syntax_mode, folder_id=file.folder_id)

    # Affichage pour les PDF
    if file_ext == '.pdf':
        return render_template('view_pdf.html', filename=file.name, file_id=file_id, folder_id=file.folder_id)

    # Affichage pour les images
    if file_ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}:
        return render_template('view_image.html', filename=file.name, file_id=file_id, folder_id=file.folder_id)

    # Sinon, proposer le téléchargement
    flash('Preview not available. Download the file to view it.', 'info')
    return redirect(url_for('download_file', file_id=file_id))

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('You do not have access to this page.', 'error')
        return render_template('user_dashboard.html')
    
    users = User.query.all()
    total_files = File.query.count()
    total_storage_used = db.session.query(db.func.sum(File.size)).scalar() or 0
    
    return render_template('admin.html',
                         users=users,
                         total_files=total_files,
                         total_storage_used=total_storage_used)

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        
        if user:
            # Here you can add logic to send reset email
            # For now, just simulate a positive response
            flash('If an account exists with this email, you will receive password reset instructions.', 'info')
            return redirect(url_for('login'))
        
        # Even if user doesn't exist, return same message for security reasons
        flash('If an account exists with this email, you will receive password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/report', methods=['GET', 'POST'])
@login_required
def report():
    if request.method == 'POST':
        title = request.form.get('title')
        content = request.form.get('content')
        group_ids = request.form.getlist('groups')
        to_all = 'to_all' in request.form
        if title and content:
            ann = Announcement(title=title, content=content, author_id=current_user.id, to_all=to_all)
            if not to_all and group_ids:
                groups = Group.query.filter(Group.id.in_(group_ids)).all()
                ann.groups = groups
            db.session.add(ann)
            db.session.commit()
            flash('Announcement published!', 'success')
        else:
            flash('Title and content required.', 'error')
        return redirect(url_for('report'))
    # Show announcements visible to user
    user_group_ids = [g.id for g in current_user.groups] if hasattr(current_user, 'groups') else []
    announcements = Announcement.query.filter(
        (Announcement.to_all == True) |
        (Announcement.groups.any(Group.id.in_(user_group_ids))) |
        (Announcement.author_id == current_user.id)
    ).order_by(Announcement.created_at.desc()).all()
    all_groups = Group.query.all()
    return render_template('announcements.html', announcements=announcements, all_groups=all_groups)

@app.route('/contact_us', methods=['GET', 'POST'])
@login_required
def contact_us():
    if request.method == 'POST':
        try:
            subject = request.form.get('subject')
            message = request.form.get('message')
            
            if not subject or not message:
                flash('Subject and message are required', 'error')
                return redirect(url_for('contact_us'))
            
            # Here you can add logic to send email
            # For example, using Flask-Mail or another service
            
            flash('Your message has been sent successfully', 'success')
            return redirect(url_for('admin_dashboard' if current_user.is_admin else 'user_dashboard'))
            
        except Exception as e:
            flash(f'An error occurred: {str(e)}', 'error')
            return redirect(url_for('contact_us'))
    
    return render_template('contact_us.html')

@app.route('/admin/panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('You do not have access to this page.', 'error')
        return render_template('user_dashboard.html')
    
    try:
        # Get data for admin panel
        users = User.query.all()
        total_files = File.query.count()
        total_folders = Folder.query.count()
        total_storage_used = db.session.query(db.func.sum(File.size)).scalar() or 0
        
        # Format total size
        if total_storage_used < 1024:
            total_storage_formatted = f"{total_storage_used} B"
        elif total_storage_used < 1024**2:
            total_storage_formatted = f"{total_storage_used/1024:.1f} KB"
        elif total_storage_used < 1024**3:
            total_storage_formatted = f"{total_storage_used/(1024**2):.1f} MB"
        else:
            total_storage_formatted = f"{total_storage_used/(1024**3):.1f} GB"
        
        # Calculate storage usage per user
        user_storage = []
        for user in users:
            user_files = File.query.filter_by(owner_id=user.id).all()
            storage_used = sum(f.size for f in user_files)
            
            # Format for display
            if storage_used < 1024**2:
                storage_formatted = f"{storage_used/1024:.1f} KB"
            elif storage_used < 1024**3:
                storage_formatted = f"{storage_used/(1024**2):.1f} MB"
            else:
                storage_formatted = f"{storage_used/(1024**3):.1f} GB"
                
            user_storage.append({
                'id': user.id,
                'email': user.email,
                'storage_used': storage_formatted,
                'storage_limit': f"{user.storage_limit/(1024**3):.1f} GB",
                'usage_percent': round((storage_used / user.storage_limit) * 100, 2) if user.storage_limit > 0 else 0
            })
        
        all_groups = Group.query.all()
        return render_template('admin_panel.html',
                             users=users,
                             user_storage=user_storage,
                             total_users=len(users),
                             total_files=total_files,
                             total_folders=total_folders,
                             total_storage=total_storage_formatted,
                             groups=all_groups)
    except Exception as e:
        flash(f'Erreur dans /admin/panel : {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

@app.route('/admin/users', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_users():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    if request.method == 'GET':
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [{
                'id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
                'storage_limit': user.storage_limit,
                'last_login': user.last_login.isoformat() if user.last_login else None
            } for user in users]
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            email = data.get('email')
            password = data.get('password')
            is_admin = data.get('is_admin', False)
            storage_limit = data.get('storage_limit', 5 * 1024 * 1024 * 1024)  # 5GB default
            
            if not email or not password:
                return jsonify({'success': False, 'message': 'Email and password are required'})
            
            if User.query.filter_by(email=email).first():
                return jsonify({'success': False, 'message': 'Email already exists'})
            
            # Create new user
            new_user = User(
                email=email,
                is_admin=is_admin,
                storage_limit=storage_limit
            )
            new_user.set_password(password)
            
            db.session.add(new_user)
            db.session.flush()  # To get user ID before commit
            
            # Generate new RSA key pair
            private_key, public_key = generate_rsa_keys()
            
            # Save only RSA keys
            save_rsa_keys(new_user.id, private_key, public_key)
            
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'User created successfully with RSA keys',
                'user': {
                    'id': new_user.id,
                    'email': new_user.email,
                    'is_admin': new_user.is_admin,
                    'storage_limit': new_user.storage_limit
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users/<int:user_id>', methods=['DELETE'])
@login_required
def delete_user(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})

    try:
        user = User.query.get_or_404(user_id)

        if user.is_admin:
            return jsonify({'success': False, 'message': 'Cannot delete an admin user'})

        if user.id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot delete your own account'})

        db.session.delete(user)
        db.session.commit()

        return jsonify({'success': True, 'message': 'User deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/folders/<int:folder_id>', methods=['DELETE'])
@login_required
def delete_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    
    # Check permissions
    if folder.owner_id != current_user.id and not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    try:
        # Recursive function to delete files and subfolders
        def delete_folder_contents(folder):
            # Delete folder files
            for file in folder.files:
                file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
                if os.path.exists(file_path):
                    os.remove(file_path)
                db.session.delete(file)
            
            # Recursively delete subfolders
            for subfolder in folder.children:
                delete_folder_contents(subfolder)
                db.session.delete(subfolder)
        
        # Delete folder contents and folder itself
        delete_folder_contents(folder)
        db.session.delete(folder)
        db.session.commit()
        
        return jsonify({'success': True})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/messagerie')
@login_required
def messagerie():
    # Get all users for contacts list
    users = User.query.filter(User.id != current_user.id).all()
    
    # Get recent conversations
    conversations = db.session.query(
        Message,
        User
    ).join(
        User,
        ((Message.sender_id == User.id) & (Message.receiver_id == current_user.id)) |
        ((Message.receiver_id == User.id) & (Message.sender_id == current_user.id))
    ).order_by(Message.created_at.desc()).all()
    
    # Organize conversations by user
    chat_partners = {}
    
    # First, add all users as potential partners
    for user in users:
        chat_partners[user.id] = {
            'user': user,
            'last_message': None,
            'unread_count': 0
        }
    
    # Then update with existing conversations
    for message, user in conversations:
        partner_id = user.id
        if partner_id in chat_partners:
            if not chat_partners[partner_id]['last_message'] or message.created_at > chat_partners[partner_id]['last_message'].created_at:
                chat_partners[partner_id]['last_message'] = message
            if not message.is_read and message.receiver_id == current_user.id:
                chat_partners[partner_id]['unread_count'] += 1
    
    # Convert dictionary to list and sort by last message date
    chat_partners_list = list(chat_partners.values())
    chat_partners_list.sort(key=lambda x: x['last_message'].created_at if x['last_message'] else datetime.min, reverse=True)
    
    return render_template('messagerie.html', 
                         users=users,
                         chat_partners=chat_partners_list)

@app.route('/api/messages', methods=['POST'])
@login_required
def send_message():
    try:
        data = request.get_json()
        receiver_id = data.get('receiver_id')
        content = data.get('content')
        
        if not receiver_id or not content:
            return jsonify({'success': False, 'message': 'Missing required fields'})
        
        # Check if receiver exists
        receiver = User.query.get_or_404(receiver_id)
        
        # Check that user is not sending message to themselves
        if receiver_id == current_user.id:
            return jsonify({'success': False, 'message': 'Cannot send message to yourself'})
        
        # 1. Generate keys for this message
        message_aes_key = generate_random_aes_key()  # AES key to encrypt message
        hmac_key = os.urandom(32)  # Separate HMAC key to verify integrity
        iv = generate_random_iv()  # Initialization vector for AES
        
        # 2. Prepare message
        timestamp = datetime.utcnow().isoformat()
        message_with_timestamp = f"{content}|{timestamp}"
        
        # 3. Generate HMAC to verify integrity
        message_hmac = generate_hmac(message_with_timestamp, hmac_key)
        
        # 4. Encrypt message with AES
        encrypted_content = encrypt_with_aes(message_with_timestamp, message_aes_key, iv)
        
        # 5. Get RSA keys
        receiver_public_key = get_user_public_key(receiver_id)
        sender_private_key = get_user_private_key(current_user.id)
        
        if not receiver_public_key or not sender_private_key:
            return jsonify({'success': False, 'message': 'Missing encryption keys'})
        
        # 6. Encrypt symmetric keys with receiver's public key
        encrypted_aes_key = encrypt_with_rsa(message_aes_key, receiver_public_key)
        encrypted_hmac_key = encrypt_with_rsa(hmac_key, receiver_public_key)
        
        # 7. Sign message with sender's private key
        message_signature = sign_message(message_with_timestamp, sender_private_key)
        
        # 8. Create message in database
        message = Message(
            sender_id=current_user.id,
            receiver_id=receiver_id,
            encrypted_content=encrypted_content,
            encrypted_aes_key=encrypted_aes_key,
            encrypted_hmac_key=encrypted_hmac_key,
            iv=iv,
            signature=message_signature,
            hmac=message_hmac,
            original_content=content  # Store original message for sender
        )
        
        db.session.add(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': {
                'id': message.id,
                'sender_id': message.sender_id,
                'content': content,
                'created_at': message.created_at.strftime('%H:%M'),
                'is_read': message.is_read
            }
        })
    except Exception as e:
        print(f"Error sending message: {str(e)}")
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/messages/<int:message_id>/delete', methods=['POST'])
@login_required
def delete_message(message_id):
    try:
        # Get message
        message = Message.query.get_or_404(message_id)
        
        # Check that user is the sender
        if message.sender_id != current_user.id:
            return jsonify({
                'success': False,
                'message': 'You are not authorized to delete this message'
            }), 403
        
        # Delete message from database
        db.session.delete(message)
        db.session.commit()
        
        return jsonify({
            'success': True,
            'message': 'Message deleted for both users'
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({
            'success': False,
            'message': str(e)
        }), 500

@app.route('/api/messages/<int:user_id>', methods=['GET'])
@login_required
def get_messages(user_id):
    try:
        # Check that requested user exists
        other_user = User.query.get_or_404(user_id)
        
        # Get messages
        messages = Message.query.filter(
            ((Message.sender_id == current_user.id) & (Message.receiver_id == user_id)) |
            ((Message.sender_id == user_id) & (Message.receiver_id == current_user.id))
        ).order_by(Message.created_at).all()
        
        # Mark messages as read
        for message in messages:
            if message.receiver_id == current_user.id and not message.is_read:
                message.is_read = True
        db.session.commit()
        
        # Decrypt messages
        decrypted_messages = []
        for message in messages:
            try:
                # If we are the receiver and message is deleted, skip it
                if message.receiver_id == current_user.id and message.is_deleted_for_receiver:
                    continue
                    
                if message.sender_id == current_user.id:
                    # If we are the sender, use original message
                    content = message.original_content
                else:
                    # If we are the receiver
                    private_key = get_user_private_key(current_user.id)
                    public_key = get_user_public_key(user_id)
                    
                    # Decrypt message
                    aes_key = decrypt_with_rsa(message.encrypted_aes_key, private_key)
                    decrypted_content = decrypt_with_aes(
                        message.encrypted_content,
                        aes_key,
                        message.iv
                    )
                    
                    # Verify signature
                    if not verify_signature(decrypted_content, message.signature, public_key):
                        print(f"Invalid signature for message {message.id}")
                        continue
                    
                    # Verify integrity with HMAC
                    hmac_key = decrypt_with_rsa(message.encrypted_hmac_key, private_key)
                    if not verify_hmac(decrypted_content, message.hmac, hmac_key):
                        print(f"Invalid HMAC for message {message.id}")
                        continue
                    
                    content, timestamp = decrypted_content.split('|')
                
                decrypted_messages.append({
                    'id': message.id,
                    'sender_id': message.sender_id,
                    'content': content,
                    'created_at': message.created_at.strftime('%H:%M'),
                    'is_read': message.is_read,
                    'is_deleted_for_receiver': message.is_deleted_for_receiver
                })
            except Exception as e:
                print(f"Error processing message {message.id}: {str(e)}")
                continue
        
        return jsonify({'success': True, 'messages': decrypted_messages})
    except Exception as e:
        print(f"Error in get_messages: {str(e)}")
        return jsonify({'success': False, 'message': str(e)})

@app.route('/api/messages/unread', methods=['GET'])
@login_required
def get_unread_count():
    count = Message.query.filter_by(
        receiver_id=current_user.id,
        is_read=False
    ).count()
    
    return jsonify({'success': True, 'count': count})

@app.route('/admin/users/<int:user_id>/reset-password', methods=['POST'])
@login_required
def reset_user_password(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        user = User.query.get_or_404(user_id)
        data = request.get_json()
        new_password = data.get('new_password')
        
        if not new_password:
            return jsonify({'success': False, 'message': 'New password is required'})
        
        user.set_password(new_password)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Password reset successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/groups', methods=['GET', 'POST', 'DELETE'])
@login_required
def manage_groups():
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    if request.method == 'GET':
        groups = Group.query.all()
        return jsonify({
            'success': True,
            'groups': [{
                'id': group.id,
                'name': group.name,
                'description': group.description,
                'user_count': group.users.count()
            } for group in groups]
        })
    
    elif request.method == 'POST':
        try:
            data = request.get_json()
            name = data.get('name')
            description = data.get('description', '')
            
            if not name:
                return jsonify({'success': False, 'message': 'Group name is required'})
            
            existing_group = Group.query.filter_by(name=name).first()
            if existing_group:
                return jsonify({'success': False, 'message': 'Group name already exists'})
            
            new_group = Group(name=name, description=description)
            db.session.add(new_group)
            db.session.commit()
            
            return jsonify({
                'success': True,
                'message': 'Group created successfully',
                'group': {
                    'id': new_group.id,
                    'name': new_group.name,
                    'description': new_group.description
                }
            })
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/groups/<int:group_id>', methods=['DELETE'])
@login_required
def delete_group(group_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        group = Group.query.get_or_404(group_id)
        
        # Remove all user associations
        group.users = []
        db.session.commit()
        
        # Delete the group
        db.session.delete(group)
        db.session.commit()
        
        return jsonify({'success': True, 'message': 'Group deleted successfully'})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/groups/<int:group_id>/users', methods=['GET', 'POST'])
@login_required
def manage_group_users(group_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    group = Group.query.get_or_404(group_id)
    if request.method == 'GET':
        users = User.query.all()
        return jsonify({
            'success': True,
            'users': [{
                'id': user.id,
                'email': user.email,
                'is_admin': user.is_admin,
                'in_group': user.is_admin or (user in group.users)
            } for user in users]
        })
    elif request.method == 'POST':
        try:
            data = request.get_json()
            user_ids = data.get('users', [])
            
            # Get all users
            users = User.query.filter(User.id.in_(user_ids)).all()
            
            # Update group users
            group.users = users
            db.session.commit()
            
            return jsonify({'success': True, 'message': 'Group users updated successfully'})
        except Exception as e:
            db.session.rollback()
            return jsonify({'success': False, 'message': str(e)})

@app.route('/admin/users/<int:user_id>/groups', methods=['GET'])
@login_required
def get_user_groups(user_id):
    if not current_user.is_admin:
        return jsonify({'success': False, 'message': 'Access denied'})
    
    try:
        user = User.query.get_or_404(user_id)
        return jsonify({
            'success': True,
            'groups': [{
                'id': group.id,
                'name': group.name,
                'description': group.description
            } for group in user.groups]
        })
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)})

@app.route('/uploads/<int:file_id>')
def serve_uploaded_file(file_id):
    file = File.query.get_or_404(file_id)
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    if not os.path.exists(file_path):
        return "File not found", 404
    return send_file(file_path, mimetype=file.mime_type or 'application/octet-stream', as_attachment=False, download_name=file.name)

def get_mime_type(filename):
    mime_type, _ = mimetypes.guess_type(filename)
    if mime_type is None:
        # Définir des types MIME par défaut pour les extensions courantes
        mime_types = {
            '.py': 'text/x-python',
            '.js': 'text/javascript',
            '.html': 'text/html',
            '.css': 'text/css',
            '.txt': 'text/plain',
            '.json': 'application/json',
            '.xml': 'application/xml',
            '.csv': 'text/csv',
            '.md': 'text/markdown',
            '.yaml': 'text/yaml',
            '.yml': 'text/yaml',
            '.ini': 'text/plain',
            '.cfg': 'text/plain',
            '.sh': 'text/x-shellscript',
            '.php': 'text/x-php'
        }
        ext = os.path.splitext(filename)[1].lower()
        return mime_types.get(ext, 'application/octet-stream')
    return mime_type

def generate_random_aes_key(length=32):
    import os
    return os.urandom(length)

def generate_hmac(message, key):
    """Génère un HMAC SHA-256 pour le message donné avec la clé donnée."""
    import hmac
    import hashlib
    import base64
    h = hmac.new(key, message.encode(), hashlib.sha256)
    return base64.b64encode(h.digest()).decode()

@app.route('/download_folder/<int:folder_id>')
@login_required
def download_folder(folder_id):
    folder = Folder.query.get_or_404(folder_id)
    # Permission check
    if not current_user.is_admin and folder.owner_id != current_user.id:
        flash('You do not have permission to download this folder.', 'error')
        return redirect(url_for('browse'))

    # Helper to recursively collect files
    def collect_files(folder, path_prefix=""):
        files = []
        for file in folder.files:
            files.append((os.path.join(path_prefix, file.name), file.filename))
        for subfolder in folder.children:
            files.extend(collect_files(subfolder, os.path.join(path_prefix, subfolder.name)))
        return files

    files_to_zip = collect_files(folder, folder.name)
    zip_buffer = io.BytesIO()
    with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zipf:
        for arcname, stored_filename in files_to_zip:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], stored_filename)
            if os.path.exists(file_path):
                zipf.write(file_path, arcname)
    zip_buffer.seek(0)
    return send_file(
        zip_buffer,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f"{folder.name}.zip"
    )

@app.route('/api/files/<int:file_id>/preview')
@login_required
def api_file_preview(file_id):
    file = File.query.get_or_404(file_id)
    if not current_user.is_admin and file.owner_id != current_user.id:
        return jsonify({'success': False, 'message': 'Access denied'}), 403

    file_ext = os.path.splitext(file.name)[1].lower()
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    mime_type = file.mime_type or 'application/octet-stream'

    # Text files
    ALLOWED_TEXT_EXTENSIONS = {
        '.txt', '.html', '.css', '.js', '.json', '.xml', '.csv', '.md', '.yaml', '.yml', '.ini', '.cfg',
    }
    if file_ext in ALLOWED_TEXT_EXTENSIONS:
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
        except UnicodeDecodeError:
            with open(file_path, 'r', encoding='latin-1') as f:
                content = f.read()
        syntax_modes = {
            '.py': 'python', '.html': 'html', '.css': 'css', '.js': 'javascript', '.json': 'json', '.xml': 'xml', '.md': 'markdown', '.yaml': 'yaml', '.yml': 'yaml'
        }
        syntax_mode = syntax_modes.get(file_ext, 'plaintext')
        return jsonify({'success': True, 'type': 'text', 'content': content, 'syntax_mode': syntax_mode, 'filename': file.name})

    # PDF files
    if file_ext == '.pdf':
        return jsonify({'success': True, 'type': 'pdf', 'url': url_for('serve_uploaded_file', file_id=file.id), 'filename': file.name})

    # Image files
    if file_ext in {'.png', '.jpg', '.jpeg', '.gif', '.bmp', '.svg', '.webp'}:
        return jsonify({'success': True, 'type': 'image', 'url': url_for('serve_uploaded_file', file_id=file.id), 'filename': file.name})

    # Otherwise
    return jsonify({'success': False, 'type': 'unsupported', 'message': 'Preview not available for this file type.'})

@app.route('/announcements/delete/<int:announcement_id>', methods=['POST'])
@login_required
def delete_announcement(announcement_id):
    ann = Announcement.query.get_or_404(announcement_id)
    if not (current_user.is_admin or current_user.id == ann.author_id):
        abort(403)
    db.session.delete(ann)
    db.session.commit()
    flash('Announcement deleted.', 'success')
    return redirect(url_for('report'))

if __name__ == '__main__':
    print("Starting Flask application...")
    app.run(debug=True)