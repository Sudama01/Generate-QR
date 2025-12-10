from flask import Flask, render_template_string, request, send_file, redirect, session, url_for, jsonify, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import qrcode
import io
import base64
from datetime import datetime, timedelta
import os

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///qrapp.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['JWT_SECRET_KEY'] = os.environ.get('JWT_SECRET_KEY', os.environ.get('SESSION_SECRET', 'super-secret-jwt'))
app.config['SECRET_KEY'] = os.environ.get('SESSION_SECRET', 'super-secret-session')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(256))
    theme = db.Column(db.String(10), default='light')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class History(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    action = db.Column(db.String(50))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

def generate_qr_bytes(data):
    img = qrcode.make(data)
    buffer = io.BytesIO()
    img.save(buffer, format='PNG')
    return buffer.getvalue()

BASE_HTML = '''
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>QR Pro App</title>
  <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/css/bootstrap.min.css" rel="stylesheet">
  <script src="https://unpkg.com/html5-qrcode" type="text/javascript"></script>
  <style>
    body { background: #f8f9fa; color: #212529; transition: all 0.3s ease; }
    body[data-theme='dark'] { background: #121212; color: #eaeaea; }
    body[data-theme='dark'] .card { background: #1e1e1e; border-color: #333; }
    body[data-theme='dark'] .form-control { background: #2d2d2d; border-color: #444; color: #eaeaea; }
    body[data-theme='dark'] .list-group-item { background: #2d2d2d; border-color: #444; color: #eaeaea; }
    .card { border-radius: 12px; }
    .qr-image { border-radius: 8px; border: 4px solid #fff; box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    #reader { width: 100%; max-width: 400px; margin: 0 auto; }
  </style>
</head>
<body data-theme="{{ theme }}">
<nav class="navbar navbar-expand-lg navbar-dark bg-dark mb-3">
  <div class="container-fluid">
    <a class="navbar-brand" href="/">QR Pro</a>
    <div class="d-flex align-items-center">
      <a href="/dashboard" class="btn btn-outline-info btn-sm me-2">Dashboard</a>
      {% if user %}
        <span class="text-light me-2">{{ user.username }}</span>
        <a href="/logout" class="btn btn-outline-light btn-sm">Logout</a>
      {% else %}
        <a href="/login" class="btn btn-outline-light btn-sm">Login</a>
      {% endif %}
    </div>
  </div>
</nav>
<div class="container">
  {% with messages = get_flashed_messages() %}
    {% if messages %}
      {% for m in messages %}
        <div class="alert alert-info alert-dismissible fade show" role="alert">
          {{ m }}
          <button type="button" class="btn-close" data-bs-dismiss="alert"></button>
        </div>
      {% endfor %}
    {% endif %}
  {% endwith %}
  {{ body|safe }}
</div>
<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.0/dist/js/bootstrap.bundle.min.js"></script>
<script>
  function toggleTheme(){
    let current = document.body.getAttribute('data-theme');
    let next = current === 'dark' ? 'light' : 'dark';
    document.body.setAttribute('data-theme', next);
    fetch('/set_theme', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({theme:next})});
  }
</script>
</body>
</html>
'''

HOME_BODY = '''
<div class="row justify-content-center">
  <div class="col-md-8">
    <div class="card p-4 shadow-sm mb-4">
      <h4 class="mb-3">Generate QR Code</h4>
      <form method="POST" action="/generate">
        <div class="mb-3">
          <input name="data" class="form-control form-control-lg" placeholder="Enter text or URL" required>
        </div>
        <div class="d-flex gap-2 flex-wrap">
          <button class="btn btn-primary btn-lg">Generate QR</button>
          <button type="button" class="btn btn-secondary" onclick="toggleTheme()">Toggle Theme</button>
        </div>
      </form>
      {% if qr_b64 %}
        <div class="text-center mt-4">
          <img src="data:image/png;base64,{{ qr_b64 }}" class="qr-image" style="width:220px;">
          <div class="mt-3">
            <a href="/download?data={{ raw }}" class="btn btn-success">Download PNG</a>
          </div>
          <p class="text-muted mt-2 small">Content: {{ raw }}</p>
        </div>
      {% endif %}
    </div>

    <div class="card p-4 shadow-sm">
      <h4 class="mb-3">Scan QR Code</h4>
      <p class="text-muted">Use your camera to scan a QR code</p>
      <div id="reader"></div>
      <div class="mt-3 p-3 bg-light rounded" id="scan-result">
        <em>No scan yet - point your camera at a QR code</em>
      </div>
    </div>
  </div>
</div>
<script>
function onScanSuccess(decodedText, decodedResult) {
  document.getElementById('scan-result').innerHTML = '<strong>Scanned:</strong> ' + decodedText + 
    '<br><a href="' + decodedText + '" target="_blank" class="btn btn-sm btn-outline-primary mt-2">Open Link</a>';
  fetch('/api/save_scan', {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({content:decodedText})});
}
function onScanFailure(error) {}
var html5QrcodeScanner = new Html5QrcodeScanner("reader", { fps: 10, qrbox: {width: 250, height: 250} }, false);
html5QrcodeScanner.render(onScanSuccess, onScanFailure);
</script>
'''

DASHBOARD_BODY = '''
<div class="row justify-content-center">
  <div class="col-md-10">
    <h2 class="mb-4">Analytics Dashboard</h2>
    <div class="row mb-4">
      <div class="col-md-3">
        <div class="card p-3 text-center shadow-sm">
          <h3 class="text-primary">{{ stats.users }}</h3>
          <p class="mb-0">Total Users</p>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center shadow-sm">
          <h3 class="text-success">{{ stats.histories }}</h3>
          <p class="mb-0">Total Actions</p>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center shadow-sm">
          <h3 class="text-info">{{ stats.gen_24h }}</h3>
          <p class="mb-0">Generated (24h)</p>
        </div>
      </div>
      <div class="col-md-3">
        <div class="card p-3 text-center shadow-sm">
          <h3 class="text-warning">{{ stats.scan_24h }}</h3>
          <p class="mb-0">Scanned (24h)</p>
        </div>
      </div>
    </div>

    <div class="card p-4 shadow-sm">
      <h5 class="mb-3">Recent Activity</h5>
      {% if recent %}
        <ul class="list-group">
          {% for h in recent %}
            <li class="list-group-item d-flex justify-content-between align-items-center">
              <span>
                <span class="badge {% if h.action == 'generated' %}bg-primary{% else %}bg-warning{% endif %} me-2">{{ h.action }}</span>
                {{ h.content[:50] }}{% if h.content|length > 50 %}...{% endif %}
              </span>
              <small class="text-muted">{{ h.timestamp.strftime('%Y-%m-%d %H:%M') }}</small>
            </li>
          {% endfor %}
        </ul>
      {% else %}
        <p class="text-muted">No activity yet</p>
      {% endif %}
    </div>
  </div>
</div>
'''

LOGIN_BODY = '''
<div class="col-md-4 mx-auto">
  <div class="card p-4 shadow-sm">
    <h4 class="mb-3">Login</h4>
    <form method="POST">
      <input class="form-control mb-3" name="username" placeholder="Username" required>
      <input class="form-control mb-3" name="password" type="password" placeholder="Password" required>
      <button class="btn btn-primary w-100">Login</button>
    </form>
    <div class="mt-3 text-center">
      No account? <a href="/register">Register here</a>
    </div>
  </div>
</div>
'''

REGISTER_BODY = '''
<div class="col-md-4 mx-auto">
  <div class="card p-4 shadow-sm">
    <h4 class="mb-3">Create Account</h4>
    <form method="POST">
      <input class="form-control mb-3" name="username" placeholder="Username" required>
      <input class="form-control mb-3" name="password" type="password" placeholder="Password" required>
      <button class="btn btn-success w-100">Register</button>
    </form>
    <div class="mt-3 text-center">
      Already have an account? <a href="/login">Login here</a>
    </div>
  </div>
</div>
'''

@app.route('/')
def index():
    user = None
    theme = 'light'
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        theme = user.theme if user else 'light'
    return render_template_string(BASE_HTML, body=render_template_string(HOME_BODY, qr_b64=None, raw=None), user=user, theme=theme)

@app.route('/generate', methods=['POST'])
def generate():
    data = request.form.get('data')
    if not data:
        return redirect('/')
    img_bytes = generate_qr_bytes(data)
    b64 = base64.b64encode(img_bytes).decode('utf-8')
    user = None
    theme = 'light'
    if 'user_id' in session:
        user = db.session.get(User, session['user_id'])
        if user:
            theme = user.theme
            db.session.add(History(user_id=user.id, action='generated', content=data))
            db.session.commit()
    return render_template_string(BASE_HTML, body=render_template_string(HOME_BODY, qr_b64=b64, raw=data), user=user, theme=theme)

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
        return render_template_string(BASE_HTML, body=LOGIN_BODY, user=None, theme='light')
    username = request.form['username']
    password = request.form['password']
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:
        session['user_id'] = user.id
        flash('Logged in successfully!')
        return redirect('/')
    flash('Invalid credentials')
    return redirect('/login')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'GET':
        return render_template_string(BASE_HTML, body=REGISTER_BODY, user=None, theme='light')
    username = request.form['username']
    password = request.form['password']
    if User.query.filter_by(username=username).first():
        flash('Username already exists')
        return redirect('/register')
    user = User(username=username, password=password)
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
def api_token():
    data = request.get_json() or {}
    username = data.get('username')
    password = data.get('password')
    user = User.query.filter_by(username=username).first()
    if not user or user.password != password:
        return jsonify({'msg': 'Bad username or password'}), 401
    token = create_access_token(identity=user.id, expires_delta=timedelta(hours=12))
    return jsonify({'access_token': token})

@app.route('/api/generate', methods=['POST'])
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
    return render_template_string(BASE_HTML, body=render_template_string(DASHBOARD_BODY, stats=data, recent=recent), user=user, theme=theme)

with app.app_context():
    db.create_all()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
