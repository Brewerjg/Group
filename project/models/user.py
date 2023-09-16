from flask_app.config.mysqlconnection import connectToMySQL
from flask import flash
# from flask_app import app
from flask_app import bcrypt
import re

EMAIL_REGEX= re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')
from flask import flash

class User:
    db="exam"
    def __init__(self, data):
        self.id = data['id']
        self.first_name = data['first_name']
        self.last_name = data['last_name']
        self.email = data['email']
        self.password= data['password']
        self.created_at = data['created_at']
        self.updated_at = data['updated_at']

    @classmethod
    def save_user(cls, form_data):
        pw_hash = bcrypt.generate_password_hash(form_data['password'])
        print(pw_hash)
        user_data= {
            'first_name': form_data['first_name'], 
            'last_name': form_data['last_name'],
            'email': form_data['email'],
            'password': pw_hash
        }
        query= '''
                INSERT INTO users
                (first_name, last_name, email, password, created_at, updated_at)
                VALUES
                (%(first_name)s, %(last_name)s, %(email)s, %(password)s, now(),now());
        '''
        results= connectToMySQL(cls.db).query_db(query, user_data)
        return results
    
    @classmethod
    def get_all(cls):
        query='SELECT * FROM users;'
        results= connectToMySQL(cls.db).query_db(query)
        users=[]
        for row in results:
            users.append(cls(row))
        return users
    
    @classmethod
    def get_user_by_email(cls, data):

        query= '''
            SELECT * FROM users
            WHERE users.email = %(email)s;
        '''
        results= connectToMySQL(cls.db).query_db(query, data)
        if results:
            one_user = cls(results[0])
            return one_user
        else:
            return False
        
    @classmethod
    def get_by_id(cls,data):
        query = "SELECT * FROM users WHERE id = %(id)s;"
        results = connectToMySQL(cls.db).query_db(query,data)
        return cls(results[0])
    
    @staticmethod
    def validate_login(form_data):
        is_valid= True
        
        data= { "email": form_data["email"]}
        valid_user = User.get_user_by_email(data)
        if not valid_user:
            flash('Invalid Crendentials', "login")
            is_valid=False
        if valid_user:
            if not bcrypt.check_password_hash(valid_user.password, form_data['password']):
                flash('Invalid Credentials','login')
                is_valid=False
        return is_valid

    @staticmethod
    def validate_register(form_data):
        is_valid= True
        data= { "email": form_data["email"]}
        valid_user = User.get_user_by_email(data)

        if len(form_data['first_name']) < 2:
            flash("First Name must be atleast 2 characters", "register")
            is_valid= False
        if len(form_data['last_name']) < 2:
            flash("Last Name must be atleast 2 characters", "register")
            is_valid= False
        if not EMAIL_REGEX.match(form_data['email']):
            flash("Invalid email address!","register")
            is_valid=False
        if valid_user:
            flash("Email already in use!", "register")
            is_valid=False
        if len(form_data['password']) < 8:
            flash("Password needs to be atleast 8 characters","register")
            is_valid=False
        if form_data['con_password'] != form_data['password']:
            flash("password and confirm password must match!","register")
            is_valid=False

        return is_valid
