from flask import Flask, request, jsonify
from flask_jwt_extended import create_access_token, set_access_cookies, JWTManager
from flask_jwt_extended import get_jwt_identity, get_jwt, verify_jwt_in_request
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import timedelta, datetime, timezone
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


# Define how early before expiration you want to refresh the token
REFRESH_WINDOW_MINUTES = 60
#Refreshing token  
@app.after_request
def refresh_expiring_jwts(response):
    try:
        #verify if jwt is valid
        verify_jwt_in_request(optional=True) 

        #asking when the token is going to expire
        exp_timestamp = get_jwt()["exp"]
        
        #asking what time is it
        now = datetime.now(timezone.utc)
        
        #looking ahead 60 minutes from now
        target_timestamp = datetime.timestamp(now + timedelta(minutes=REFRESH_WINDOW_MINUTES))
        
        #asking if the key will espire in that 60 minutes
        if target_timestamp > exp_timestamp:
            
            #then set a new key and save in cookies
            access_token = create_access_token(identity=get_jwt_identity())
            set_access_cookies(response, access_token)
        return response
    except (RuntimeError, KeyError):
      #return response if jwt is invalid
        return response



@app.route('/signup', methods=['POST'])
def sign():
    data = request.get_json()
    firstname = data.get('firstname')
    lastname = data.get('lastname')
    email = data.get('email')
    password = data.get('password')


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
            return jsonify({"Error": f"missing fields: {Missing_fields}"}), 400
    
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

        #FIX THIS MISSING FIELDS 
        Missing_fields = []
        if not email:
            Missing_fields.append('email')
        if not password:
            Missing_fields.append('password')
        if Missing_fields:
            return jsonify({"Error": f"Missing_fields: {Missing_fields}"}), 400
        
        #finds user by email
        existing_user = User.query.filter_by(email=email).first()
        if not existing_user:
             return jsonify({'message': 'Invalid email'}), 401
        
        #hashes the entered password and comapare it to the hash password in the db
        if check_password_hash(existing_user.password, password):
            pass
        else:
            return jsonify({'message': 'Invalid password'}), 401
        
        
        #create an access token for the user to verify their identity when visiting a protected route
        access_token = create_access_token(identity=email)
        
        response = jsonify({
             'msg': 'logged in successfully',
               'access_token':access_token})
        #this add a set cookie header so when the user gets the response the token is automatically stored in the browser's cookie storage
        set_access_cookies(response, access_token)
        return response

    

with app.app_context():
    db.create_all()
    
if __name__ == '__main__':
    app.run(debug=True)
