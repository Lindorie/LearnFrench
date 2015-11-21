import ConfigParser
import sqlite3

from flask import Flask, request, session, redirect, url_for, abort, render_template, flash, g
from flask.ext.bcrypt import Bcrypt

app = Flask(__name__)
bcrypt = Bcrypt(app)
db_location = 'var/data.db'

# FUNCTIONS

def init(app):
    config = ConfigParser.ConfigParser()
    config_location = "etc/config.cfg"
    try:
        config.read(config_location)

        app.config['DEBUG'] = config.get("config", "debug")
        app.config['ip_address'] = config.get("config", "ip_address")
        app.config['port'] = config.get("config", "port")
        app.config['url'] = config.get("config", "url")
        app.config['username'] = config.get("config", "username")
        app.config['password'] = config.get("config", "password")

    except:
        print ('Could not read config from: '), config_location

# Database functions

def get_db():
    db = getattr(g, 'db', None)
    if db is None:
        db = sqlite3.connect(db_location)
        g.db = db
        db.row_factory = sqlite3.Row
    return db

@app.teardown_appcontext
def close_db_connection(exception):
    db = getattr(g, 'db', None)
    if db is None:
        db.close()

def init_db():
    with app.app_context():
        db = get_db()
        with app.open_resource('schema.sql', mode='r') as f:
            db.cursor().executescript(f.read())
        db.commit()

def query_db(query, args=(), one=False):
    db = get_db()
    cur = db.execute(query, args)
    rv = [dict((cur.description[idx][0], value) for idx, value in enumerate(row)) for row in cur.fetchall()]
    return (rv[0] if rv else None) if one else rv

# ROUTING

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        # Check if the fields are not empty
        if request.form['username'] != '' and request.form['password'] != '':
            # Check if the username exists in the database
            query = 'SELECT * FROM users WHERE username = ?'
            user = query_db(query, [request.form['username']])
            if user:
                # Check if the passwords are identical
                testPassword = bcrypt.check_password_hash(user['password'], request.form['password'])
                if testPassword:
                    session['logged_in'] = True
                    flash('You were logged in.')
                    return redirect(url_for('home'))
                else:
                    error = 'Invalid password'
            else:
                error = "This username doesn't exist."
        else:
            error = "All the fields are mandatory. Please provide your username and your password"
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out.')
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        error = []
        form = request.form
        # Check if the username exists
        query = 'SELECT * FROM users WHERE username = ?'
        testUsername = query_db(query, [request.form['username']])
        if testUsername:
            error.append("Sorry, this username is not available. Please choose another one")
        # Check if the passwords are identical
        if request.form['password'] != request.form['password2']:
            error.append("Please enter the same password in both of the password fields")
        # Check if the email address is already used
        query = 'SELECT * FROM users WHERE email = ?'
        testEmail = query_db(query, [request.form['email']])
        if testEmail:
            error.append("The email address provided is already used by the user " + testEmail['username'])
        # Insert in the database if everything is ok
        if not error:
            # Hash the password
            password = bcrypt.generate_password_hash(request.form['password'])
            # Insert
            db = get_db()
            db.cursor().execute('INSERT INTO users (username, password, email) VALUES (?,?,?)', [request.form['username'], password, request.form['email']])
            db.commit()
            flash('You were successfully registered. Try to log in!')
        return render_template('register.html', form=form, error=error)
    return render_template('register.html')


if __name__ == '__main__':
    init(app)
    app.run(
        host = app.config['ip_address'],
        port = int(app.config['port'])
    )