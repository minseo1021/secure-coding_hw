# Tiny Second-hand Shopping Platform (Flask-based - Minimal but Secure)

from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///tinyshop.db'
app.config['JWT_SECRET_KEY'] = 'super-secret-key'
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)

# ---------------- Models ---------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    bio = db.Column(db.Text, default='')
    is_admin = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Integer)
    image_url = db.Column(db.String(255))
    owner_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    content = db.Column(db.Text)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    target_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    target_product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=True)
    reason = db.Column(db.Text)
    status = db.Column(db.String(50), default='pending')

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    receiver_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    amount = db.Column(db.Integer)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)

# ---------------- Helpers ---------------- #
def admin_required(fn):
    @wraps(fn)
    @jwt_required()
    def wrapper(*args, **kwargs):
        user_id = get_jwt_identity()
        user = User.query.get(user_id)
        if not user or not user.is_admin:
            return jsonify({'msg': 'Admin only'}), 403
        return fn(*args, **kwargs)
    return wrapper

# ---------------- Auth Routes ---------------- #
@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_pw = bcrypt.generate_password_hash(data['password']).decode('utf-8')
    user = User(username=data['username'], email=data['email'], password=hashed_pw)
    db.session.add(user)
    db.session.commit()
    return jsonify({'msg': 'User registered'})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and bcrypt.check_password_hash(user.password, data['password']):
        token = create_access_token(identity=user.id)
        return jsonify({'token': token})
    return jsonify({'msg': 'Invalid credentials'}), 401

# ---------------- Product Routes ---------------- #
@app.route('/products', methods=['POST'])
@jwt_required()
def add_product():
    user_id = get_jwt_identity()
    data = request.get_json()
    product = Product(title=data['title'], description=data['description'], price=data['price'], image_url=data.get('image_url', ''), owner_id=user_id)
    db.session.add(product)
    db.session.commit()
    return jsonify({'msg': 'Product added'})

@app.route('/products', methods=['GET'])
def list_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'title': p.title, 'price': p.price} for p in products])

@app.route('/products/<int:pid>', methods=['GET'])
def get_product(pid):
    product = Product.query.get_or_404(pid)
    return jsonify({'id': product.id, 'title': product.title, 'description': product.description, 'price': product.price})

# ---------------- Messaging Routes ---------------- #
@app.route('/messages', methods=['POST'])
@jwt_required()
def send_message():
    user_id = get_jwt_identity()
    data = request.get_json()
    msg = Message(sender_id=user_id, receiver_id=data['receiver_id'], content=data['content'])
    db.session.add(msg)
    db.session.commit()
    return jsonify({'msg': 'Message sent'})

# ---------------- Report Routes ---------------- #
@app.route('/reports', methods=['POST'])
@jwt_required()
def report():
    user_id = get_jwt_identity()
    data = request.get_json()
    rpt = Report(reporter_id=user_id, target_user_id=data.get('target_user_id'), target_product_id=data.get('target_product_id'), reason=data['reason'])
    db.session.add(rpt)
    db.session.commit()
    return jsonify({'msg': 'Reported'})

@app.route('/admin/reports', methods=['GET'])
@admin_required
def get_reports():
    reports = Report.query.all()
    return jsonify([{'id': r.id, 'reason': r.reason, 'status': r.status} for r in reports])

@app.route('/admin/reports/<int:rid>', methods=['PUT'])
@admin_required
def resolve_report(rid):
    report = Report.query.get_or_404(rid)
    report.status = 'resolved'
    db.session.commit()
    return jsonify({'msg': 'Report resolved'})

# ---------------- Transaction Routes ---------------- #
@app.route('/transactions', methods=['POST'])
@jwt_required()
def send_money():
    user_id = get_jwt_identity()
    data = request.get_json()
    transaction = Transaction(sender_id=user_id, receiver_id=data['receiver_id'], amount=data['amount'])
    db.session.add(transaction)
    db.session.commit()
    return jsonify({'msg': 'Money sent'})

# ---------------- Entry Point ---------------- #
if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
