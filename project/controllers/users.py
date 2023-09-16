from flask import render_template, redirect, request, session
from flask_app import app
from flask_app.models.user import User 


@app.route('/')
def index():
    return redirect('/user/login')

@app.route('/user/login')
def login():
    if 'user_id' in session:
        return redirect('/dashboard')

    return render_template('index.html')

@app.route('/user/register', methods=['POST'])
def register():
    if not User.validate_register(request.form):
        return redirect('/')
    new_user = User.save_user(request.form)
    email_data={
        'email':request.form['email']
    }
    returning_user= User.get_user_by_email(email_data)
    session['user_id']= returning_user.id
    return redirect('/dashboard')


@app.route('/user/login', methods=['POST'])
def login_user():
    user = User.validate_login(request.form)
    if not user:
        return redirect('/dashboard')
    email_data={
        'email':request.form['email']
    }
    returning_user= User.get_user_by_email(email_data)
    session['user_id']= returning_user.id
    return redirect('/dashboard')


@app.route('/user/logout')
def logout():
    if 'user_id' in session:
        session.pop('user_id')
    return redirect('/user/login')

