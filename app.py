from flask import Flask, render_template, request, redirect, session, flash
from flask_wtf.csrf import CSRFProtect
import sqlite3
import re
import bcrypt

app = Flask(__name__)
app.secret_key = 'your_strong_random_secret_key_here'

# Enable CSRF protection
csrf = CSRFProtect(app)

# Database initialization
def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY, username TEXT UNIQUE, password TEXT)''')
    conn.commit()
    conn.close()

init_db()

# Input validation for username and password
def validate_input(username, password):
    if not re.match(r'^[a-zA-Z0-9_]{4,20}$', username):
        return False, "Username must be 4-20 characters long and contain only letters, numbers, and underscores."
    if not re.match(r'^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$', password):
        return False, "Password must be at least 8 characters long and include at least one letter and one number."
    return True, ""

# Hash password using bcrypt
def hash_password(password):
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password.decode('utf-8')  # Convert bytes to string for storage

# Verify password using bcrypt
def check_password(hashed_password, input_password):
    hashed_password_bytes = hashed_password.encode('utf-8')  # Convert back to bytes
    return bcrypt.checkpw(input_password.encode(), hashed_password_bytes)

# Sign-up route
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        is_valid, message = validate_input(username, password)
        if not is_valid:
            flash(message)
            return redirect('/signup')

        hashed_password = hash_password(password)

        try:
            conn = sqlite3.connect('users.db')
            c = conn.cursor()
            c.execute("INSERT INTO users (username, password) VALUES (?, ?)", (username, hashed_password))
            conn.commit()
            conn.close()
            flash('Sign-up successful! Please log in.')
            return redirect('/login')
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose another.')
            return redirect('/signup')

    return render_template('signup.html')

# Login route
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect('users.db')
        c = conn.cursor()
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user = c.fetchone()
        conn.close()

        if user and check_password(user[2], password):
            session['user_id'] = user[0]
            session['username'] = user[1]
            flash('Login successful!')
            return redirect('/')  # Redirect to the dashboard
        else:
            flash('Invalid username or password.')
            return redirect('/login')

    return render_template('login.html')

# Logout route
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.')
    return redirect('/login')

# Home route (Dashboard)
@app.route('/')
def home():
    if 'user_id' in session:
        return render_template('dashboard.html')  # Render the dashboard page
    return redirect('/login')

if __name__ == '__main__':
    app.run(debug=True)