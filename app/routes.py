 
from flask import render_template, request, redirect, url_for, flash
from app import app

@app.route('/')
def home():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Handle login logic here
        username = request.form['username']
        password = request.form['password']
        # Add your login validation logic
        return redirect(url_for('home'))  # Redirect after successful login
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        # Handle signup logic here
        username = request.form['username']
        password = request.form['password']
        # Add your signup logic (e.g., save to the database)
        return redirect(url_for('home'))  # Redirect after successful signup
    return render_template('signup.html')
