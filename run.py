import jwt
import datetime
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from bisHash.hashing import bis_hash, verify_password, is_strong_password
from app.models import db, User  # Adjust based on your project structure
import os


app = Flask(__name__, static_folder=os.path.join('app', 'static'), template_folder=os.path.join('app', 'templates'))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///example.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.secret_key = 'your_secret_key_here'  # Change to a secure key
app.config['SESSION_COOKIE_NAME'] = 'Token'  # Make sure the session is properly configured
db.init_app(app)

@app.route('/')
def home():
    return redirect(url_for('login'))  # Redirect to the login page



@app.route('/login', methods=['GET', 'POST'])  # Allow both GET and POST
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        # Fetch user based on username or email
        user = User.query.filter(
             (User.email == email)
        ).first()

        if user and verify_password(user.password, user.email, password):  # Verify hashed password
            session['user_id'] = user.id  # Log the user in by storing their ID in session
            # Generate JWT token
            token = jwt.encode(
                {
                    "user_id": user.id,
                    "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=1)  # Token expiry time (1 hour)
                },
                app.secret_key,  # Use your Flask app's secret key for signing the token
                algorithm="HS256"  # You can use HS256 or any other algorithm you prefer
            )

            # Store the token in session (optional for backend usage)
            session['auth_token'] = token
            print(f"JWT Token: {token}")
            
            decoded_token = jwt.decode(token, app.secret_key, algorithms=["HS256"])
            print(decoded_token)  # Check the decoded token

            return redirect(url_for('index'))  # Redirect to the index page after login
        else:
            return "Invalid credentials", 401  # Unauthorized

    return render_template('login.html')  # Render the login page for GET requests

@app.route('/protected', methods=['GET'])
def protected():
    token = request.headers.get("Authorization")
    if not token:
        return jsonify({"message": "Token missing"}), 403

    try:
        decoded = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        print(f"Decoded Token: {decoded}")
        user_id = decoded["user_id"]
        return f"Protected Content: Welcome user {user_id}"
        # Optional: Fetch user info if needed
        return jsonify({"message": "Access granted", "user_id": user_id})
    except jwt.ExpiredSignatureError:
        return jsonify({"message": "Token expired"}), 403
    except jwt.InvalidTokenError:
        return jsonify({"message": "Invalid token"}), 403
    
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

@app.route('/check_session')
def check_session():
    token = request.headers.get('Authorization')  # Get the token from the Authorization header
    
    if not token:
        return 'Unauthorized', 401  # Token is missing
    
    try:
        # Remove 'Bearer ' prefix if it exists
        token = token.split(' ')[1]
        
        # Decode and validate the token
        decoded_token = jwt.decode(token, app.secret_key, algorithms=["HS256"])
        return 'Authenticated', 200  # Token is valid

    except jwt.ExpiredSignatureError:
        return 'Token expired', 401  # Token expired
    except jwt.InvalidTokenError:
        return 'Invalid token', 401  # Invalid token

@app.route('/logout', methods=['POST'])  # Make sure to include methods=['POST']
def logout():
    session.clear()  # Clear the session data
    return redirect(url_for('login'))  # Redirect to the login page

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Ensure tables are created
        app.run(port=80)
