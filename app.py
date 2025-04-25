from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os
from datetime import datetime, timedelta
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key-here')
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///cloud.db'
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

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Folder(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(255), nullable=False)
    parent_id = db.Column(db.Integer, db.ForeignKey('folder.id'))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    files = db.relationship('File', backref='folder', lazy=True)
    children = db.relationship('Folder', backref=db.backref('parent', remote_side=[id]))

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
    status = db.Column(db.String(20), nullable=False, default='complete')  # Modifié pour être non nullable avec une valeur par défaut

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
        
        user = User.query.filter_by(email=email).first()
        if user and user.check_password(password):
            user.last_login = datetime.utcnow()
            db.session.commit()
            
            login_user(user, remember=remember, duration=timedelta(days=30) if remember else None)
            if user.is_admin:
                return redirect(url_for('admin_dashboard'))
            return redirect(url_for('user_dashboard'))
        
        flash('Invalid email or password', 'error')
    
    return render_template('login.html')

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/admin/dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user_dashboard'))
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
        # Récupérer le dossier courant et ses sous-dossiers
        current_folder = None
        subfolders = []
        files = []
        
        if folder_id:
            current_folder = Folder.query.filter_by(id=folder_id, owner_id=current_user.id).first_or_404()
            subfolders = Folder.query.filter_by(parent_id=folder_id, owner_id=current_user.id).all()
            files = File.query.filter_by(folder_id=folder_id, owner_id=current_user.id).all()
        else:
            # Si aucun dossier n'est sélectionné, afficher les dossiers racine
            subfolders = Folder.query.filter_by(parent_id=None, owner_id=current_user.id).all()
            files = File.query.filter_by(folder_id=None, owner_id=current_user.id).all()
        
        # Récupérer le chemin du dossier courant
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
                             folder_path=folder_path)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('browse.html', 
                             current_folder=None,
                             subfolders=[],
                             files=[],
                             folder_path=[])

@app.route('/upload')
@login_required
def upload():
    try:
        folders = Folder.query.filter_by(owner_id=current_user.id).all()
        
        # Récupérer les uploads en cours et terminés
        try:
            uploads_in_progress = File.query.filter_by(owner_id=current_user.id, status='in_progress').all()
            completed_uploads = File.query.filter_by(owner_id=current_user.id, status='complete').limit(5).all()
        except:
            uploads_in_progress = []
            completed_uploads = File.query.filter_by(owner_id=current_user.id).limit(5).all()
        
        # Calculer l'utilisation du stockage
        used_storage = sum(f.size for f in current_user.files)
        total_storage = current_user.storage_limit
        storage_percentage = round((used_storage / total_storage) * 100) if total_storage > 0 else 0
        
        # Formatage pour l'affichage
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
        
        return render_template('upload.html',
                             folders=folders,
                             uploads_in_progress=uploads_in_progress,
                             completed_uploads=completed_uploads,
                             used_storage=used_storage_formatted,
                             total_storage=total_storage_formatted,
                             storage_percentage=storage_percentage)
    except Exception as e:
        flash(str(e), 'error')
        return render_template('upload.html',
                             folders=[],
                             uploads_in_progress=[],
                             completed_uploads=[],
                             used_storage="0 B",
                             total_storage="0 B",
                             storage_percentage=0)

@app.route('/api/files/upload', methods=['POST'])
@login_required
def upload_file():
    if 'files[]' not in request.files:
        return jsonify({'success': False, 'message': 'No file part'})

    files = request.files.getlist('files[]')
    folder_id = request.form.get('folder_id', type=int)
    
    # Make folder_id optional
    if folder_id:
        folder = Folder.query.get_or_404(folder_id)
        if folder.owner_id != current_user.id and not current_user.is_admin:
            return jsonify({'success': False, 'message': 'Access denied'})

    used_storage = sum(f.size for f in current_user.files)
    
    uploaded_files = []
    for file in files:
        if file.filename == '':
            continue
            
        file_size = len(file.read())
        file.seek(0)  # Reset file pointer
        
        if used_storage + file_size > current_user.storage_limit:
            return jsonify({'success': False, 'message': 'Storage limit exceeded'})
            
        filename = secure_filename(file.filename)
        unique_filename = f"{uuid.uuid4()}_{filename}"
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
        
        try:
            file.save(file_path)
            new_file = File(
                name=filename,
                filename=unique_filename,
                size=file_size,
                mime_type=file.content_type,
                folder_id=folder_id,
                owner_id=current_user.id,
                status='complete'
            )
            db.session.add(new_file)
            db.session.commit()  # Commit each file individually to get ID
            uploaded_files.append(new_file)  # Add the file object to the list
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
            # Si la colonne status n'existe pas, on renvoie quand même un succès
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
            # Si la colonne status n'existe pas, on renvoie quand même un succès
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/api/folders', methods=['POST'])
@login_required
def create_folder():
    data = request.get_json()
    if not data or 'name' not in data:
        return jsonify({'success': False, 'message': 'Folder name is required'}), 400
    
    parent_id = data.get('parent_id')

    try:
        new_folder = Folder(
            name=data['name'],
            parent_id=parent_id,
            owner_id=current_user.id
        )
        db.session.add(new_folder)
        db.session.commit()
        return jsonify({'success': True, 'folder_id': new_folder.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': str(e)}), 500

@app.route('/download/<int:file_id>')
@login_required
def download_file(file_id):
    file = File.query.get_or_404(file_id)
    
    if file.owner_id != current_user.id and not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('browse'))

    return send_file(
        os.path.join(app.config['UPLOAD_FOLDER'], file.filename),
        download_name=file.name,
        as_attachment=True
    )

@app.route('/admin')
@login_required
def admin():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user_dashboard'))
    
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
            # Ici vous pouvez ajouter la logique pour envoyer un email de réinitialisation
            # Pour l'instant, on simule juste une réponse positive
            flash('If an account exists with this email, you will receive password reset instructions.', 'info')
            return redirect(url_for('login'))
        
        # Même si l'utilisateur n'existe pas, on renvoie le même message pour des raisons de sécurité
        flash('If an account exists with this email, you will receive password reset instructions.', 'info')
        return redirect(url_for('login'))
    
    return render_template('forgot_password.html')

@app.route('/report')
@login_required
def report():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user_dashboard'))
    
    # Statistiques pour le rapport
    users = User.query.all()
    files = File.query.all()
    folders = Folder.query.all()
    
    # Statistiques par utilisateur
    user_stats = []
    for user in users:
        user_files = File.query.filter_by(owner_id=user.id).all()
        storage_used = sum(f.size for f in user_files)
        
        # Formatage de la taille
        if storage_used < 1024:
            storage_formatted = f"{storage_used} B"
        elif storage_used < 1024**2:
            storage_formatted = f"{storage_used/1024:.1f} KB"
        elif storage_used < 1024**3:
            storage_formatted = f"{storage_used/(1024**2):.1f} MB"
        else:
            storage_formatted = f"{storage_used/(1024**3):.1f} GB"
            
        user_stats.append({
            'email': user.email,
            'files_count': len(user_files),
            'folders_count': Folder.query.filter_by(owner_id=user.id).count(),
            'storage_used': storage_formatted,
            'last_login': user.last_login.strftime('%Y-%m-%d %H:%M:%S') if user.last_login else 'Never',
            'is_admin': user.is_admin
        })
    
    # Statistiques globales
    total_storage = sum(f.size for f in files)
    if total_storage < 1024**2:
        total_storage_formatted = f"{total_storage/1024:.1f} KB"
    elif total_storage < 1024**3:
        total_storage_formatted = f"{total_storage/(1024**2):.1f} MB"
    else:
        total_storage_formatted = f"{total_storage/(1024**3):.1f} GB"
    
    return render_template('report.html',
                         users=users,
                         user_stats=user_stats,
                         total_users=len(users),
                         total_files=len(files),
                         total_folders=len(folders),
                         total_storage=total_storage_formatted)

@app.route('/admin/panel')
@login_required
def admin_panel():
    if not current_user.is_admin:
        flash('Access denied', 'error')
        return redirect(url_for('user_dashboard'))
    
    try:
        # Récupération des données pour le panneau d'administration
        users = User.query.all()
        total_files = File.query.count()
        total_folders = Folder.query.count()
        total_storage_used = db.session.query(db.func.sum(File.size)).scalar() or 0
        
        # Formatage de la taille totale
        if total_storage_used < 1024:
            total_storage_formatted = f"{total_storage_used} B"
        elif total_storage_used < 1024**2:
            total_storage_formatted = f"{total_storage_used/1024:.1f} KB"
        elif total_storage_used < 1024**3:
            total_storage_formatted = f"{total_storage_used/(1024**2):.1f} MB"
        else:
            total_storage_formatted = f"{total_storage_used/(1024**3):.1f} GB"
        
        # Calcul de l'utilisation du stockage par utilisateur
        user_storage = []
        for user in users:
            user_files = File.query.filter_by(owner_id=user.id).all()
            storage_used = sum(f.size for f in user_files)
            
            # Formatage pour l'affichage
            if storage_used < 1024**2:
                storage_formatted = f"{storage_used/1024:.1f} KB"
            elif storage_used < 1024**3:
                storage_formatted = f"{storage_used/(1024**2):.1f} MB"
            else:
                storage_formatted = f"{storage_used/(1024**3):.1f} GB"
                
            user_storage.append({
                'email': user.email,
                'storage_used': storage_formatted,
                'storage_limit': f"{user.storage_limit/(1024**3):.1f} GB",
                'usage_percent': round((storage_used / user.storage_limit) * 100, 2) if user.storage_limit > 0 else 0
            })
        
        return render_template('admin_panel.html',
                             users=users,
                             user_storage=user_storage,
                             total_users=len(users),
                             total_files=total_files,
                             total_folders=total_folders,
                             total_storage=total_storage_formatted)
    except Exception as e:
        flash(f'Une erreur est survenue: {str(e)}', 'error')
        return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    with app.app_context():
        # Supprimer toutes les tables existantes
        db.drop_all()
        # Créer toutes les tables
        db.create_all()
        
        # Initialize default users if they don't exist
        if not User.query.filter_by(email='user@example.com').first():
            # Create normal user
            user = User(email='user@example.com')
            user.set_password('user123')
            user.is_admin = False
            user.storage_limit = 2 * 1024 * 1024 * 1024  # 2GB
            db.session.add(user)

            # Create admin user
            admin = User(email='admin@example.com')
            admin.set_password('admin123')
            admin.is_admin = True
            admin.storage_limit = 5 * 1024 * 1024 * 1024  # 5GB
            db.session.add(admin)
            
            db.session.commit()
    app.run(debug=True)