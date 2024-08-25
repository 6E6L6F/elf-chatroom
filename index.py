from flask import Flask, render_template, redirect, url_for , request 
from flask_wtf import FlaskForm
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from flask_socketio import SocketIO, emit, leave_room, join_room
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import Session

from werkzeug.security import generate_password_hash, check_password_hash

from wtforms import StringField, PasswordField, DateField, TimeField, SelectField 
from wtforms.validators import DataRequired

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

import uuid
from enum import Enum
from datetime import datetime

from config import Config
from functions import *

app = Flask(__name__, template_folder="template/" , static_folder="static/")
app.config['SECRET_KEY'] = Config.SECRET_KEY
app.config['SQLALCHEMY_DATABASE_URI'] = Config.SQLALCHEMY_DATABASE_URI
app.config["KEYS"] = Config.KEYS

db = SQLAlchemy(app)
socketio = SocketIO(app)
login_manager = LoginManager(app)
session = Session()

rooms = {}

class UserRole(Enum):
    user = 1
    super_admin = 2

class Security:
    def encrypt_message(self, message):
        with open('keys/public_key.pem', 'rb') as f:
            public_key = serialization.load_ssh_public_key(
                f.read(),
                backend=default_backend()
            )
        encrypted_message = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return encrypted_message

    def decrypt_message(self,encrypted_message):
        with open('keys/private_key.pem', 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        decrypted_message = private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return decrypted_message.decode()
    

class PrivateMessage(db.Model, Security):
    id = db.Column(db.Integer, primary_key=True)
    message_id = db.Column(db.String(64), unique=True, nullable=False)
    timestamp = db.Column(db.Time, default=datetime.today().time)
    date = db.Column(db.Date, default=datetime.today().date)
    encrypted_text = db.Column(db.Text, nullable=False)
    
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True), foreign_keys=[user_id])
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient = db.relationship('User', backref=db.backref('received_private_messages', lazy=True), foreign_keys=[recipient_id])
    
    reply_to = db.Column(db.String(64), db.ForeignKey('private_message.message_id'), nullable=True)
    reply_message = db.relationship('PrivateMessage', remote_side=[message_id], backref='replies')

    def __init__(self, text, user, timestamp, date, recipient, reply_to=None):
        self.message_id = uuid.uuid4().hex
        self.text = text
        self.user = user
        self.recipient = recipient
        self.timestamp = timestamp
        self.date = date
        self.encrypted_text = self.encrypt_message(text)
        self.reply_to = reply_to

    def decrypt(self):
        return self.decrypt_message(self.encrypted_text)


    
class EditUserForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    date = DateField('Date', validators=[DataRequired()])
    time = TimeField('Time', validators=[DataRequired()])
    role = SelectField('Role', choices=[('user', 'User'),('super_admin', 'Super Admin')], validators=[DataRequired()])
    
    def validate_password(self, field):
        if not field.data:
            return True
        return DataRequired()(self, field)
    
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    password = db.Column(db.String(128), nullable=False)
    role = db.Column(db.Enum(UserRole), default=UserRole.user)
    date = db.Column(db.Date)
    time = db.Column(db.Time)
    received_messages = db.relationship('Message', backref=db.backref('sender', lazy=True))

    def set_password(self, password):
        self.password = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password, password)

class Message(db.Model , Security):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    user = db.relationship('User', backref=db.backref('messages', lazy=True))
    timestamp = db.Column(db.Time, default=datetime.today().time)
    date = db.Column(db.Date, default=datetime.today().date)
    encrypted_text = db.Column(db.Text, nullable=False)
    user = db.relationship('User', backref=db.backref('sent_by', lazy=True))

    def __init__(self, text, user, timestamp, date):
        self.text = text
        self.user = user
        self.timestamp = timestamp
        self.date = date
        self.encrypted_text = self.encrypt_message(text)

    def decrypt(self):
        return self.decrypt_message(self.encrypted_text)
    


def has_permission_to_chat(user1, user2):
    if user1.role == UserRole.super_admin:
        return True
    elif user1.role == UserRole.admin and user2.role in [UserRole.admin, UserRole.moderator, UserRole.user]:
        return True
    elif user1.role == UserRole.moderator and user2.role in [UserRole.moderator, UserRole.user]:
        return True
    else:
        return False
    
def get_users_with_permission_to_chat(user):
    if user.role == UserRole.super_admin:
        return User.query.all()
    elif user.role == UserRole.admin:
        return User.query.filter(User.role.in_([UserRole.admin, UserRole.moderator, UserRole.user])).filter(User.id != user.id).all()
    elif user.role == UserRole.moderator:
        return User.query.filter(User.role.in_([UserRole.moderator, UserRole.user])).filter(User.id != user.id).all()
    else:
        return []
    

@app.route("/")
def index():
    if not current_user.is_authenticated:
        return redirect(url_for('login'))
    
    return render_template("index.html", current_user=current_user.username , role=str(current_user.role))


@app.route("/admin")
@login_required
def admin():
    if current_user.role != UserRole.super_admin :
        return render_template("404.html")
    
    users = User.query.all()
    return render_template("admin.html", users=users)

@app.route('/admin/user/<int:user_id>/edit', methods=['GET', 'POST'])
@login_required
def admin_user_edit(user_id):
    user = User.query.get_or_404(user_id)
    form = EditUserForm(obj=user)
    if request.method == "POST":
        if form.username.data:
            user.username = form.username.data

        if form.password.data:
            user.password = generate_password_hash(form.password.data)

        if form.date.data:
            user.date = form.date.data

        if form.time.data:
            user.time = form.time.data

        if form.role.data:
            user.role = UserRole[form.role.data]

        db.session.commit()

        return render_template('edit_user.html', form=form, user=user)

    return render_template('edit_user.html', form=form, user=user)


@app.route("/admin/user/<int:user_id>/delete")
@login_required
def admin_user_delete(user_id):
    if current_user.role == UserRole.super_admin:
        return redirect(url_for('index'))
    
    user = User.query.get(user_id)
    if user is None:
        return redirect(url_for('admin'))
    
    messages = Message.query.filter_by(user_id=user_id).all()
    for message in messages:
        db.session.delete(message)
    db.session.delete(user)
    db.session.commit()
    
    return redirect(url_for('admin'))

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            if user.role == UserRole.super_admin:
                return redirect(url_for('admin'))
            else:
                return redirect(url_for('index'))
        else:
            return render_template("login.html", error="Username or password invalid")
    return render_template("login.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            return render_template("register.html", error="Username is not valid")
    
        user = User(username=username)
        user.set_password(password)
        user.date = datetime.today().date()
        user.time = datetime.today().time()
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('login'))
    
    return render_template("register.html")

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))



@socketio.on('connect')
def handle_connect():
    messages = Message.query.all()
    for message in messages:
        emit(
            'message', 
            {
                'text': message.decrypt(),
                'username': message.user.username,
                'timestamp': message.timestamp.strftime('%H:%M:%S'),
                'date': message.date.strftime('%Y-%m-%d')
            },
            broadcast=False
        )
            
@socketio.on('message')
def handle_message(data):
    if current_user.is_authenticated:
        message_text = data['text'].strip()
        print(message_text)
        if message_text: 
            message = Message(text=message_text, user=current_user, timestamp=datetime.today().time(), date=datetime.today().date())            
            db.session.add(message)
            db.session.commit()
            timestamp_str = message.timestamp.strftime('%H:%M:%S')
            date_str = message.date.strftime('%Y-%m-%d')
            emit('message', 
                    {
                        'text': message.decrypt(),
                        'username': message.user.username,
                        'timestamp': timestamp_str,
                        'date': date_str
                    },
                    broadcast=True
                )

        else:
            return
    else:
        return redirect("login")

@socketio.on('typing')
def handle_typing():
    emit(
        'typing', 
            {
                'username': current_user.username
            },
            broadcast=True
        )

@socketio.on('stop_typing')
def handle_stop_typing():
    emit(
        'stop_typing', 
            {
                'username': current_user.username
            },
            broadcast=True
        )



def create_default_admin():
    if not User.query.filter_by(username='admin').first():
        admin = User(username='admin', role=UserRole.super_admin)
        admin.set_password('OIFnkjlsdf&*890sd@*(#')
        db.session.add(admin)
        db.session.commit()
    
if __name__ == '__main__':
    if not app.config["KEYS"]:
        private_key, public_key = generate_keys()
        if "keys" not in os.listdir():
            mkdir("keys")
            
        with open('keys/private_key.pem', 'wb') as f:
            f.write(private_key)

        with open('keys/public_key.pem', 'wb') as f:
            f.write(public_key)
            
    with app.app_context():
        db.create_all()
        create_default_admin()
    socketio.run(app , debug=True , host="0.0.0.0")
    
    
