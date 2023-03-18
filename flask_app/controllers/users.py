from flask import render_template, redirect, request, session, flash
from flask_app import app
from flask_bcrypt import Bcrypt 
bcrypt = Bcrypt(app)
from flask_app.models.user import User

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/users/create', methods=['POST'])
def create_user():
    if not User.validate(request.form):
        return redirect('/')
    if User.check_user(request.form):
        return redirect('/')
    hashed_pw = bcrypt.generate_password_hash(request.form['password'])
    user_data = {
        **request.form,
        'password' : hashed_pw
    }
    user_id = User.save(user_data)
    session['user_id'] = user_id

    return redirect('/dashboard')

@app.route('/users/login', methods=['POST'])
def login_user():
    user_in_db = User.get_user_by_email(request.form)
    if not user_in_db:
        flash('User not found', 'login')
        return redirect('/')
    if not bcrypt.check_password_hash(user_in_db.password, request.form['password']):
        flash('Invalid login credentials', 'login')
        return redirect('/')
    session['user_id'] = user_in_db.id
    return redirect('/dashboard')

@app.route('/dashboard')
def show_dash():
    if 'user_id' not in session:
        return redirect('/')
    
    logged_user = User.get_user_by_id(session['user_id'])
    print(logged_user)
    return render_template('dashboard.html', user = logged_user)

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')