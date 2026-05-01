import os
import boto3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

app = Flask(__name__)

# --- CONFIGURACIÓN DE SEGURIDAD ---
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-123')

# --- CONFIGURACIÓN DE AWS S3 ---
S3_BUCKET = os.environ.get('S3_BUCKET_NAME')
S3_REGION = "us-east-1"
s3 = boto3.client('s3', region_name=S3_REGION)

# --- CONFIGURACIÓN DE BASE DE DATOS (SQLite) ---
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proyecto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- CONFIGURACIÓN DE MAILTRAP ---
app.config['MAIL_SERVER'] = 'sandbox.smtp.mailtrap.io'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'b41bd3d9240f12' 
app.config['MAIL_PASSWORD'] = '0b9df69b875a11' 
mail = Mail(app)

# Serializador para tokens de seguridad
s = URLSafeTimedSerializer(app.secret_key)

# --- MODELOS DE DATOS ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_verified = db.Column(db.Boolean, default=False)
    images = db.relationship('Image', backref='owner', lazy=True)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    upload_date = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- RUTAS ---

@app.route('/')
def login_page():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form.get('username')
    password = request.form.get('password')
    user = User.query.filter_by(username=username).first()

    if user and check_password_hash(user.password, password):
        session['user_id'] = user.id
        session['username'] = user.username
        return redirect(url_for('dashboard'))
    
    flash("Usuario o contraseña incorrectos")
    return redirect(url_for('login_page'))

@app.route('/register_page')
def register_page():
    return render_template('register.html')

@app.route('/register', methods=['POST'])
def register():
    username = request.form.get('username')
    email = request.form.get('email') 
    password = request.form.get('password')
    
    if User.query.filter((User.username == username) | (User.email == email)).first():
        flash("El usuario o email ya existen")
        return redirect(url_for('register_page'))
    
    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, email=email, password=hashed_pw, is_verified=False)
    db.session.add(new_user)
    db.session.commit()

    try:
        token = s.dumps(email, salt='email-confirm')
        link = url_for('confirm_email', token=token, _external=True)
        msg = Message('Confirma tu cuenta', sender=app.config['MAIL_USERNAME'], recipients=[email])
        msg.body = f'Haz clic aquí para verificar tu cuenta: {link}'
        mail.send(msg)
        flash("Registro exitoso. Revisa tu Inbox en Mailtrap para verificar tu cuenta.")
    except Exception as e:
        flash("Usuario creado pero hubo un problema enviando el correo.")
        print(f"Error mail: {e}")

    return redirect(url_for('login_page'))

@app.route('/confirm_email/<token>')
def confirm_email(token):
    try:
        email = s.loads(token, salt='email-confirm', max_age=3600)
    except:
        return "<h1>El enlace es inválido o ha expirado.</h1>"
    
    user = User.query.filter_by(email=email).first_or_404()
    user.is_verified = True
    db.session.commit()
    flash("¡Cuenta verificada! Ahora puedes iniciar sesión y subir imágenes.")
    return redirect(url_for('login_page'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    user = User.query.get(session['user_id'])
    user_images = Image.query.filter_by(user_id=user.id).all()
    base_url = f"https://{S3_BUCKET}.s3.amazonaws.com/"
    
    return render_template('dashboard.html', 
                           username=user.username, 
                           images=user_images, 
                           base_url=base_url,
                           is_verified=user.is_verified)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    user = User.query.get(session['user_id'])
    
    # Verificación de seguridad antes de procesar el archivo
    if not user.is_verified:
        flash("¡Error! Debes confirmar tu correo antes de subir archivos.")
        return redirect(url_for('dashboard'))

    file = request.files.get('file')
    if file and file.filename != '':
        filename = f"user{session['user_id']}_{file.filename}"
        try:
            s3.upload_fileobj(file, S3_BUCKET, filename)
            new_img = Image(filename=filename, user_id=session['user_id'])
            db.session.add(new_img)
            db.session.commit()
            flash("Imagen subida correctamente")
        except Exception as e:
            flash(f"Error al subir a S3: {str(e)}")
            
    return redirect(url_for('dashboard'))

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login_page'))

# --- INICIO DE LA APP ---
if __name__ == '__main__':
    with app.app_context():
        db.create_all() 
    app.run(host='0.0.0.0', port=5000)