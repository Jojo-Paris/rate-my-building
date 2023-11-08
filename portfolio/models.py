from portfolio import db, login_manager
from portfolio import bcrypt
from flask_login import UserMixin
from datetime import datetime

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class User(db.Model, UserMixin):
    id = db.Column(db.Integer(), primary_key=True)
    firstName = db.Column(db.String(length=30), nullable=False, unique=False)
    lastName = db.Column(db.String(length=30), nullable=False, unique=False)
    username = db.Column(db.String(length=30), nullable=False, unique=True)
    email_address = db.Column(db.String(length=50), nullable=False, unique=True)
    password_hash = db.Column(db.String(length=60), nullable=False)
    userReview = db.relationship('Review', backref='owned_user', lazy=True)

    @property
    def password(self):
        return self.password
    
    @password.setter
    def password(self, plain_text_password):
        self.password_hash = bcrypt.generate_password_hash(plain_text_password).decode('utf-8')

    def check_password_correction(self, attempted_password):
        return bcrypt.check_password_hash(self.password_hash, attempted_password)

class Review(db.Model):
    id = db.Column(db.Integer(), primary_key=True)
    buildingName = db.Column(db.String(length=10), nullable=False)
    likes = db.Column(db.Integer(), nullable=False, default = 0)
    dislikes = db.Column(db.Integer(), nullable=False, default = 0)
    aesthetics = db.Column(db.Integer(), nullable=False)
    cleanliness = db.Column(db.Integer(), nullable=False)
    peripherals = db.Column(db.Integer(), nullable=False)
    vibes = db.Column(db.Integer(), nullable=False)
    description = db.Column(db.String(length=750), nullable=False)
    date_created = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    owner = db.Column(db.Integer(), db.ForeignKey('user.id'))