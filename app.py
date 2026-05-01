import os
import boto3
from flask import Flask, render_template, request, redirect, url_for, session, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)

# --- CONFIGURACIÓN DE SEGURIDAD ---
# Usamos el respaldo solo para desarrollo, en AWS fallará si no está la variable
app.secret_key = os.environ.get('FLASK_SECRET_KEY', 'dev-key-123')

# --- CONFIGURACIÓN DE AWS S3 ---
S3_BUCKET = os.environ.get('S3_BUCKET_NAME')
S3_REGION = "us-east-1"

# Boto3 detecta automáticamente el LabRole de la instancia EC2
s3 = boto3.client('s3', region_name=S3_REGION)

# --- CONFIGURACIÓN DE BASE DE DATOS (SQLite) ---
# Se creará un archivo llamado 'proyecto.db' en la misma carpeta
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///proyecto.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# --- MODELOS DE DATOS (Módulo 6) ---
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    images = db.relationship('Image', backref='owner', lazy=True)

class Image(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    filename = db.Column(db.String(200), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

# --- RUTAS DE LA APLICACIÓN ---

@app.route('/')
def login_page():
    # Si ya está logueado, mandarlo al dashboard
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
    password = request.form.get('password')
    
    if User.query.filter_by(username=username).first():
        flash("El nombre de usuario ya existe")
        return redirect(url_for('register_page'))
    
    hashed_pw = generate_password_hash(password)
    new_user = User(username=username, password=hashed_pw)
    db.session.add(new_user)
    db.session.commit()
    
    flash("Registro exitoso. Por favor inicia sesión.")
    return redirect(url_for('login_page'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))
    
    # Módulo 5: Traer solo las imágenes del usuario actual
    user_images = Image.query.filter_by(user_id=session['user_id']).all()
    
    # URL base para mostrar las fotos directamente desde S3
    base_url = f"https://{S3_BUCKET}.s3.amazonaws.com/"
    
    return render_template('dashboard.html', 
                           username=session['username'], 
                           images=user_images, 
                           base_url=base_url)

@app.route('/upload', methods=['POST'])
def upload():
    if 'user_id' not in session:
        return redirect(url_for('login_page'))

    file = request.files.get('file')
    if file and file.filename != '':
        # Renombramos el archivo para evitar duplicados en S3
        filename = f"user{session['user_id']}_{file.filename}"
        
        try:
            # Módulo 4: Subida directa a S3
            s3.upload_fileobj(file, S3_BUCKET, filename)
            
            # Guardar referencia en SQLite
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
        db.create_all() # Crea la base de datos y las tablas al arrancar
    app.run(host='0.0.0.0', port=5000)