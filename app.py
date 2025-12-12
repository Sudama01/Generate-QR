from flask import Flask, request, render_template, send_file, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_wtf.csrf import CSRFProtect, generate_csrf
from werkzeug.security import generate_password_hash, check_password_hash
import qrcode
import io
import base64
from datetime import datetime, timedelta
import os
import secrets

app = Flask(__name__)

secret_key = os.environ.get('SESSION_SECRET')
if not secret_key:
    secret_key = secrets.token_hex(32)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///qrapp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', secret_key)
app.config['SECRET_KEY'] = secret_key
app.config['WTF_CSRF_ENABLED'] = True

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)
csrf = CSRFProtect(app)

class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(256))
    theme = db.Column(db.String(10), default='light')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class History(db.Model):
    __tablename__ = 'history'
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=True)
    action = db.Column(db.String(50))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def generate_qr_bytes(data):
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()

@app.route('/')
def index():
    user = None
    theme = 'light'
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        theme = user.theme if user else 'light'

    csrf = generate_csrf()

    return render_template(
        "base.html",
        body=render_template("home.html", qr_b64=None, raw=None,csrf_token=csrf),
        user=user,
        theme=theme
    )



@app.route('/generate', methods=['POST'])
def generate():
    data = request.form.get('data')
    print(data)
    if not data:
        print("No data passed from client")
        return redirect('/')
        
    img_bytes = generate_qr_bytes(f"upi://pay?pa={data}")
    b64 = base64.b64encode(img_bytes).decode('utf-8')
    user = None
    theme = 'light'
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            theme = user.theme
            db.session.add(History(user_id=user.id, action='generated', content=data))
            db.session.commit()
    csrf = generate_csrf()
    return render_template("base.html",
        body=render_template("home.html", qr_b64=b64, raw=data, csrf_token=csrf), user=user, theme=theme)


@app.route('/download')
def download():
    data = request.args.get('data')
    if not data:
        return redirect('/')
    img_bytes = generate_qr_bytes(data)
    buffer = io.BytesIO(img_bytes)
    buffer.seek(0)
    return send_file(buffer, as_attachment=True, download_name='qr.png', mimetype='image/png')

@app.route('/set_theme', methods=['POST'])
@csrf.exempt
def set_theme():
    payload = request.get_json() or {}
    theme = payload.get('theme', 'light')
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            user.theme = theme
            db.session.commit()
    return ('', 204)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'GET':
        return render_template("base.html", body=render_template("login.html"), user=None, theme='light')
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.check_password(password):
        session['user_id'] = user.id
        flash('Logged in successfully!')
        return redirect('/')
    flash('Invalid credentials')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template("base.html", body=render_template("register.html"), user=None, theme='light')
    username = request.form['username']
    password = request.form['password']
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect('/register')
    user = User(username=username)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    session['user_id'] = user.id
    flash('Account created successfully!')
    return redirect('/')

@app.route('/logout')
def logout():
    session.clear()
    flash('Logged out')
    return redirect('/')

@app.route('/api/token', methods=['POST'])
@csrf.exempt
def api_token():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or not user.check_password(password):
        return jsonify({'msg': 'Bad username or password'}), 401
    token = create_access_token(identity=user.id, expires_delta=timedelta(hours=12))
    return jsonify({'access_token': token})

@app.route('/api/generate', methods=['POST'])
@csrf.exempt
@jwt_required()
def api_generate():
    uid = get_jwt_identity()
    payload = request.get_json() or {}
    content = payload.get('content')
    if not content:
        return jsonify({'msg': 'missing content'}), 400
    img_bytes = generate_qr_bytes(content)
    b64 = base64.b64encode(img_bytes).decode('utf-8')
    db.session.add(History(user_id=uid, action='generated', content=content))
    db.session.commit()
    return jsonify({'qr_base64': b64})

@app.route('/api/save_scan', methods=['POST'])
@csrf.exempt
def api_save_scan():
    payload = request.get_json() or {}
    content = payload.get('content')
    uid = session.get('user_id')
    db.session.add(History(user_id=uid, action='scanned', content=content))
    db.session.commit()
    return ('', 204)

@app.route('/dashboard')
def dashboard():
    users_count = User.query.count()
    histories_count = History.query.count()
    since = datetime.utcnow() - timedelta(days=1)
    gen_24h = History.query.filter(History.action == 'generated', History.timestamp >= since).count()
    scan_24h = History.query.filter(History.action == 'scanned', History.timestamp >= since).count()
    recent = History.query.order_by(History.timestamp.desc()).limit(10).all()
    data = {'users': users_count, 'histories': histories_count, 'gen_24h': gen_24h, 'scan_24h': scan_24h}
    user = db.session.get(User, session.get('user_id')) if session.get('user_id') else None
    theme = user.theme if user else 'light'
    return render_template("base.html", body=render_template("dashboard.html", stats=data, recent=recent), user=user, theme=theme)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
