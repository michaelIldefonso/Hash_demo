from flask import Flask, render_template, request, redirect, url_for, session
from bisHash.hashing import bis_hash, verify_password, is_strong_password
from app.models import db, User  # Adjust based on your project structure
import os

app = Flask(__name__, static_folder=os.path.join('app', 'static'), template_folder=os.path.join('app', 'templates'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'  # Change to a secure key

db.init_app(app)

@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to the login page

@app.route('/login', methods=['GET', 'POST'])  # Allow both GET and POST
def login():
    if request.method == 'POST':
        username_or_email = request.form.get('username_or_email')
        password = request.form.get('password')

        # Fetch user based on username or email
        user = User.query.filter(
            (User.userName == username_or_email) | (User.email == username_or_email)
        ).first()

        if user and verify_password(user.password, user.email, password):  # Verify hashed password
            session['user_id'] = user.id  # Log the user in by storing their ID in session
            return redirect(url_for('index'))  # Redirect to the index page after login
        else:
            return "Invalid credentials", 401  # Unauthorized

    return render_template('login.html')  # Render the login page for GET requests

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        userName = request.form.get('userName')
        fullName = request.form.get('fullName')
        email = request.form.get('email')
        contact = request.form.get('contact')
        password = request.form.get('password')

        # Ensure password is strong before proceeding
        if not is_strong_password(password):
            return "Password does not meet strength requirements.", 400
        
        hashed_password = bis_hash(email, password)  # Hash the password

        if not userName or not fullName:
            return "UserName and FullName cannot be empty!", 400

        # Create new user instance
        new_user = User(userName=userName, fullName=fullName, email=email,
                        contact=contact, password=hashed_password)

        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))  # Redirect to login after adding user

    return render_template('signup.html')  # Render the signup page for GET requests

@app.route('/index')  # Define the index route
def index():
    if 'user_id' not in session:  # Check if user is logged in
        return redirect(url_for('login'))  # Redirect to login if not logged in
    users = User.query.all()  # Fetch users from the database
    return render_template('index.html', users=users)  # Render index.html with user data

@app.route('/add', methods=['POST'])
def add_user():
    userName = request.form.get('userName')
    fullName = request.form.get('fullName')
    email = request.form.get('email')
    contact = request.form.get('contact')
    password = request.form.get('password')
    hashed_password = bis_hash(email, password)

    if not userName or not fullName:
        return "UserName and FullName cannot be empty!", 400
    
   

    new_user = User(userName=userName, fullName=fullName, email=email,
                    contact=contact, password=hashed_password)

    db.session.add(new_user)
    db.session.commit()
    return redirect(url_for('login'))  # Redirect to login after adding user

@app.route('/delete/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    try:
        user = User.query.get(user_id)  # Find the user by ID
        if user:
            db.session.delete(user)  # Remove the user from the session
            db.session.commit()  # Commit the changes to the database
            return redirect(url_for('index'))  # Redirect to the index page
        else:
            return "User not found!", 404  # Handle the case where the user doesn't exist
    except Exception as e:
        print(f"Error deleting user: {e}")
        return "An error occurred while trying to delete the user.", 500

@app.route('/logout', methods=['POST'])  # Make sure to include methods=['POST']
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
        app.run(debug=True)
