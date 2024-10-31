from flask import Flask, render_template, request, redirect, url_for
from app.models import db, User  # Adjust based on your project structure
import os

app = Flask(__name__, template_folder=os.path.join('app', 'templates'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db.init_app(app)

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

    if not userName or not fullName:
        return "UserName and FullName cannot be empty!", 400

    new_user = User(userName=userName, fullName=fullName, email=email,
                    contact=contact, password=password)

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('index'))

@app.route('/signup')
def signup():
    return render_template('signup.html')

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
    app.run(debug=True)
