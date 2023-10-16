from datetime import datetime
from qr_points_app import db, login_manager
from flask_login import UserMixin
import random

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    first_name = db.Column(db.String(120), nullable=False)
    last_name = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    points = db.Column(db.Integer, default=0)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)  # New field for group relationship
    qrcodes = db.relationship('QRCode', back_populates='created_by')
    user_avatar = db.Column(db.String(120), nullable=True)

    __table_args__ = (db.UniqueConstraint('first_name', 'last_name', name='uq_fullname'), )
    def set_default_avatar(self):
        if not self.user_avatar:
            random_num = random.randint(10, 59)  # Choose a random number between 10 and 59
            self.user_avatar = f'static/avatardefault/50 Monsters Avatar Icons_{random_num}.svg'

class Group(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    code = db.Column(db.String(60), unique=True, nullable=False)
    is_archived = db.Column(db.Boolean, default=False)
    users = db.relationship('User', backref='group', lazy=True)
    qrcodes = db.relationship('QRCode', backref='group', cascade='all, delete-orphan')
    

class QRCode(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    value = db.Column(db.Integer, nullable=False)
    description = db.Column(db.String(120), nullable=True)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=True)
    scanned_qrs = db.relationship('ScannedQR', back_populates='qr_code', cascade='all, delete-orphan')
    date_created = db.Column(db.Date, nullable=True, default=datetime.utcnow)
    created_by_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    created_by = db.relationship('User', back_populates='qrcodes')
    status = db.Column(db.String(120), nullable=True, default=datetime.utcnow)  # New status field
    is_checkin = db.Column(db.Boolean, default=False)

class ScannedQR(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    qr_code_id = db.Column(db.Integer, db.ForeignKey('qr_code.id'), nullable=False)  # Corrected ForeignKey
    points_received = db.Column(db.Integer, nullable=False)
    last_scanned = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)  # New field
    qr_code = db.relationship('QRCode', back_populates='scanned_qrs')

class LeaderboardEntry(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    group_id = db.Column(db.Integer, db.ForeignKey('group.id'), nullable=False)
    points = db.Column(db.Integer, default=0)

class Checkin(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    qr_code_id = db.Column(db.Integer, db.ForeignKey('qr_code.id'), nullable=False)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    date_created = db.Column(db.String(120), nullable=True, default='Absent')    
    user = db.relationship('User')
    qr_code = db.relationship('QRCode')
