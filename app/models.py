from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(80), unique=True, nullable=False)
    fullName = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(128), nullable=False)  # Password stored as plain text

    def __repr__(self):
        return f'<User {self.userName}>'
