from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, set_access_cookies, JWTManager
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import os

db = SQLAlchemy()

app = Flask(__name__)

# JWT Secret Key
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'your-default-secret')

#setting up sqlite connection
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('SQLALCHEMY_DATABASE_URI',"sqlite:///site.db")
# This disables SQLAlchemy's event system for tracking object modifications (saves memory and avoids warnings)
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
# Initializing extensions
db.init_app(app)
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    firstname = db.Column(db.String(50))
    lastname = db.Column(db.String(50))
    email = db.Column(db.String(150), unique=True)
    password = db.Column(db.String(300))


@app.route('/signup', methods=['POST'])
def sign():
    data = request.get_json()
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = data.get('email')
    password = data.get('email')

    #FIX IT
    Missing_fields = []
    if not firstname:
        Missing_fields.append('firstname')
    if not lastname:
        Missing_fields.append('lastname')
    if not email:
        Missing_fields.append('email')
    if not password:
        Missing_fields.append('password')
    if Missing_fields:
            return jsonify({f"missing fields, {Missing_fields}"}), 400
    
    existing_user = User.query.filter_by(email=email).first()
    if existing_user:
        return jsonify({'message': 'Email already exist'}), 400
    
    hashed_password = generate_password_hash(password)
    
    new_user = User(firstname=firstname, lastname=lastname, email=email, password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'Account created successfully'}), 201



@app.route('/login', methods=['POST'])
def log():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    Missing_fields = []
    if not email:
        Missing_fields.append('email')
    if not password:
        Missing_fields.append('password')
    if Missing_fields:
        return jsonify({f"missing_fields, {Missing_fields}"}), 400

    add = User.query.filter_by(email=email).first()
    if not add:
        return jsonify({'message': 'Invalid email'}), 400
    #FIX HERE
    if check_password_hash(add.password, password):
        pass
    else:
        return jsonify({'message': 'Invalid password'}), 400
    
    access_token = create_access_token(identity=email)

    response = jsonify({
        'message': 'Login successful',
        'access_token': access_token
    })
    set_access_cookies(response, access_token)
    return response

    







with app.app_context():
    db.create_all()
    
if __name__ == '__main__':
    app.run(debug=True)
