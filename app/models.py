from flask import Flask, render_template, request, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'  # Use SQLite for this example
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Define the User model
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userName = db.Column(db.String(80), unique=True, nullable=False)
    fullName = db.Column(db.String(120), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    contact = db.Column(db.String(15), nullable=False)
    password = db.Column(db.String(128), nullable=False)

    def __repr__(self):
        return f'<User {self.username}>'

@app.route('/')
def index():
    users = User.query.all()
    return render_template('index.html', users=users)

@app.route('/add', methods=['POST'])
def add_user():
    userName = request.form.get('userName')
    fullName = request.form.get('fullName')
    email = request.form.get('email')
    contact = request.form.get('contact')
    password = request.form.get('password')
    
    # Hash the password for security
    hashed_password = generate_password_hash(password, method='sha256')
    
    new_user = User(userName=userName, fullName=fullName, email=email,
                    contact=contact, password=hashed_password)
    
    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('index'))

if __name__ == '__main__':
    db.create_all()  # Create database tables
    app.run(debug=True)

