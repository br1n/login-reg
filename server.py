from flask import Flask, redirect, render_template, session, request, flash
from mysqlconnection import MySQLConnector
import flask_bcrypt
import re
EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$')

app = Flask(__name__)
bcrypt = flask_bcrypt.Bcrypt(app)
app.secret_key = "henlo"

mysql = MySQLConnector(app,'login_regdb')


@app.route('/')
def index():
    return render_template('index.html', title="Home")

@app.route('/success')
def success():
    return render_template('success.html')

@app.route('/register', methods=["POST"])
def register():
   #validate 
    valid = True
    form = request.form

    #first_name validation
    if form["first_name"] == "":
        valid = False
        flash("First name cannot be blank")

    elif not form["first_name"].isalpha():
        valid = False
        flash("First name must be alphabetical only")

    elif len(form["first_name"]) <= 2:
        valid = False
        flash("First name must be more than 2 characters")

    #last_name validation
    if form["last_name"] == "":
        valid = False
        flash("Last name cannot be blank")

    elif not form["last_name"].isalpha():
        valid = False
        flash("Last name must be alphabetical only")

    elif len(form["last_name"]) <= 2:
        valid = False
        flash("Last name must be more than 2 characters")

    #email validation
    if form["email"] == "":
        valid = False
        flash("Email cannot be blank")
    
    if not EMAIL_REGEX.match(form['email']):
        valid = False
        flash("Not a valid email")

    #password/confirm password validation
    if form["password"] == "":
        valid = False
        flash("Password cannot be blank")

    elif len(form["password"]) <= 8:
        valid = False
        flash("Password must be more than 8 characters")

    if form["confirm password"] == "":
        valid = False
        flash("Confirm password cannot be blank")

    if not form["password"] == form["confirm password"]:
        valid = False
        flash("confirm password does not match password")
    
    if not valid:
        return redirect('/')
    
    else:
        #bcrypt/pw hash
        pw_hash = bcrypt.generate_password_hash(form["password"])
        query = "INSERT INTO `login_regdb`.`users` (`first_name`, `last_name`, `email`, `password`, `created_at`, `updated_at`) VALUES (:first_name, :last_name, :email, :password, NOW(), NOW());"
        data = {
            "first_name":form["first_name"],
            "last_name":form["last_name"],
            "email":form["email"],
            "password":pw_hash
        }
        mysql.query_db(query, data)    
        flash("You are now registered - Please login.")
        return redirect('/')

#login validation and bcrypt    
@app.route('/login',methods=["POST"])
def login():
    valid = True
    form = request.form
    #email validation
    if form["email"] == "":
        valid = False
        flash("Login email cannot be blank")
    
    if not EMAIL_REGEX.match(form['email']):
        valid = False
        flash("Not a valid login email or password")

    if form["password"] == "":
        valid = False
        flash("Login password cannot be blank")

    if not valid:
        return redirect('/')

    else:
        query = "SELECT * FROM `login_regdb`.`users` WHERE email = :email_data"
         #data: {"email_data" : form["email"]} 
        dbdata = mysql.query_db(query,{"email_data":form["email"]})  
        if len(dbdata) > 0:
            user = dbdata[0]
            if bcrypt.check_password_hash(user['password'], form['password']):
                session["logged_id"] = user["id"]
                return redirect('/success')
        
        flash("Incorrect login information")    
        return redirect('/')


app.run(debug=True)