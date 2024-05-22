from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime
from flask_login import LoginManager, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask import jsonify
# Assuming you have a variable `Base` that represents your SQLAlchemy declarative base
from sqlalchemy.ext.declarative import declarative_base

# context.configure(url='sqlite:///travel.db', target_metadata=target_metadata)
app = Flask(__name__)
app.config['SECRET_KEY'] = '7777'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///travel.db'  # Use SQLite for simplicity
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
class User(db.Model): 
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(80), nullable=False)

class Destination(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    iname = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    currency = db.Column(db.String(10))
    image_url = db.Column(db.String(200))

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    userid = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    destinationid = db.Column(db.Integer, db.ForeignKey('destination.id'), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    test=db.Column(db.String(200))
# Database initialization
with app.app_context():
    db.create_all()

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))
@app.route('/')
def home():
    destinations = Destination.query.all()  # Fetch all destinations
    comments=Comment.query.all()
    return render_template('home.html', destinations=destinations,comments=comments)
  
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        email = request.form.get('email')
        password = request.form.get('password')

        # hashed_password = generate_password_hash(password, method='sha256')
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(name=name, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()

        flash('Registration successful.', 'success')
        return redirect(url_for('login'))

    return render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')

        user = User.query.filter_by(email=email).first()
        if not user:
            flash('Email does not exist.', 'danger')
            return redirect(url_for('login'))
        
        if not check_password_hash(user.password, password):
            flash('Password incorrect.', 'danger')
            return redirect(url_for('login'))

        session['user_id'] = user.id
        flash('Logged in successfully.', 'success')
        return redirect(url_for('home'))

    return render_template('login.html')
@app.route('/add_destination', methods=['GET', 'POST'])
# @login_required
def add_destination():
    if request.method == 'POST':
        iname = request.form.get('iname')
        description = request.form.get('description')
        currency = request.form.get('currency')
        image_url = request.form.get('image_url')

        new_destination = Destination(iname=iname, description=description, currency=currency, image_url=image_url)
        db.session.add(new_destination)
        db.session.commit()

        flash('Destination added successfully.', 'success')
        return redirect(url_for('home'))

    return render_template('add_destination.html')

@app.route('/post_comment/<int:destination_id>', methods=['POST'])
def post_comment(destination_id):
    content = request.form.get('content')
    user_id = session.get('user_id')

    new_comment = Comment(userid=user_id, destinationid=destination_id, test=content)
    # new_comment = Comment(userid=user_id, destinationid=destination_id, content="Some content")
    db.session.add(new_comment)
    db.session.commit()

    # Return JSON response indicating success
    return jsonify({'status': 'success'})

    # return redirect(url_for('destination', destination_id=destination_id))
@app.route('/destination/<int:destination_id>')
def destination(destination_id):
    destination = Destination.query.get_or_404(destination_id)
    comments = Comment.query.filter_by(destinationid=destination_id).all()
    return render_template('destination.html', destination=destination, comments=comments)

@app.route('/logout')
# @login_required
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'info')
    return redirect(url_for('login')) 
if __name__ == '__main__':
   
    app.run(debug=True)
