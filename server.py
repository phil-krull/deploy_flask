from flask import Flask, render_template, request, redirect, flash, session
from mysqlconnection import connectToMySQL  # import the function that will return an instance of a connection
import re
from flask_bcrypt import Bcrypt


EMAIL_REGEX = re.compile(r'^[a-zA-Z0-9.+_-]+@[a-zA-Z0-9._-]+\.[a-zA-Z]+$') 
app = Flask(__name__)
bcrypt = Bcrypt(app)
app.secret_key = 'My super secret key'

#  ______________Get Requests______________
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/dashboard")
def dashboard():
    if 'user_id' not in session:
        flash('Must be logged in to access this page')
        return redirect('/')

    user_id = session['user_id']
    # Get the logged in user
    mysql = connectToMySQL('private_wall')
    query = "SELECT * FROM users WHERE id = %(session_user_id)s"
    data = {
        'session_user_id': user_id
    }
    user = mysql.query_db(query, data)

    # Get the messages for the logged in user
    mysql = connectToMySQL('private_wall')
    query = "SELECT messages.id, messages.content, users.first_name AS sender, messages.created_at FROM private_wall.messages JOIN users ON messages.sender_id = users.id WHERE messages.reciever_id = %(session_user_id)s;"
    data = {
        'session_user_id': user_id
    }
    user_messages = mysql.query_db(query, data)

    # Get all the users, except for the logged in user
    mysql = connectToMySQL('private_wall')
    query = "SELECT id, first_name FROM users WHERE id != %(session_user_id)s"
    data = {
        'session_user_id': user_id
    }
    other_users_not_logged_in = mysql.query_db(query, data)

    # Get the Number of messages sent
    mysql = connectToMySQL('private_wall')
    query = "SELECT COUNT(id) AS num_sent FROM messages WHERE sender_id = %(session_user_id)s"
    data = {
        'session_user_id': user_id
    }
    number_of_messages_sent = mysql.query_db(query, data)


    return render_template("dashboard.html", user = user[0], messages = user_messages, other_users = other_users_not_logged_in, sent_messages = number_of_messages_sent)

# _________________Post Requests_______________
@app.route('/register', methods=['post'])
def register():
    # valiation
    is_valid = True
    print(request.form)
    if len(request.form['form_first_name']) < 1:
        flash('First Name is required!')
        is_valid = False

    if not EMAIL_REGEX.match(request.form['form_email']):
        flash("Invalid email address!")
        is_valid = False
    else:
        # check to see if it's unique(db query)
        mysql = connectToMySQL('private_wall')
        query = "SELECT * FROM users WHERE email = %(email_from_form)s"
        data = {
            'email_from_form': request.form['form_email']
        }
        result = mysql.query_db(query, data)
        # check the result for a match
        if len(result) > 0:
            # the email exist in the DB
            flash('Email already exist')
            is_valid = False

    if request.form['form_password'] != request.form['form_confirm_password']:
        flash('Passwords must match!')
        is_valid = False

    # if passed the validations
    if is_valid == False:
        # False - display the errors, redirect to index
        return redirect('/')
    else:
        # True - create the user, save in session, redirect to dashboard
        # create the hashed password
        pw_hash = bcrypt.generate_password_hash(request.form['form_password'])
        mysql = connectToMySQL('private_wall')
        query = "INSERT INTO users (first_name, last_name, email, password) VALUES (%(f_name)s, %(l_name)s, %(email)s, %(hashed_pw)s);"
        data = {
            'f_name': request.form['form_first_name'],
            'l_name': request.form['form_last_name'],
            'email': request.form['form_email'],
            'hashed_pw': pw_hash
        }
        user_id = mysql.query_db(query, data)
        # save the id in session
        session['user_id'] = user_id

        return redirect('/dashboard')

@app.route('/logout', methods = ['post'])
def logout():
    session.clear()
    return redirect('/')

@app.route('/login', methods = ['post'])
def login():
    # check for user in DB
    mysql = connectToMySQL('private_wall')
    query = "SELECT * FROM users WHERE email = %(email_from_form)s"
    data = {
        'email_from_form': request.form['form_email']
    }
    user = mysql.query_db(query, data)
    # check the result for a match
    # if user
    if len(user) > 0:
        # the email exist in the DB
        # compare password
        if bcrypt.check_password_hash(user[0]['password'], request.form['form_password']) == True:
        # if match
            # login in the user
            session['user_id'] = user[0]['id']
            return redirect('/dashboard')
        # else
        else:
            # error message to index
            flash('Invalid email/password combination!')
            return redirect('/')
    # no user
    else:
        # error message to index
        flash('Email not in database')
        return redirect('/')



@app.route('/messages/<message_id>/delete', methods=['post'])
def delete_message(message_id):
    mysql = connectToMySQL('private_wall')
    query = "DELETE FROM messages WHERE id = %(message_id_from_browser)s"
    data = {
        'message_id_from_browser': message_id # or request.form['message_id']
    }
    mysql.query_db(query, data)
    return redirect('/dashboard')

@app.route('/messages', methods = ['post'])
def add_message():
    mysql = connectToMySQL('private_wall')
    query = "INSERT INTO `private_wall`.`messages` (`content`, `sender_id`, `reciever_id`) VALUES (%(form_content)s, %(logged_in_user)s, %(form_reciever)s);"
    data = {
        'form_content': request.form['content'],
        'logged_in_user': session['user_id'],
        'form_reciever': request.form['reciever_id']
    }
    mysql.query_db(query, data)
    return redirect('/dashboard')

if __name__ == "__main__":
    app.run(debug=True)
