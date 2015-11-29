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

        app.secret_key = "supersecretkey"

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
            # Check if it is admin
            if request.form['username'] == 'admin':
                # Check the password for admin
                if request.form['password'] == app.config['password']:
                    session['logged_in'] = True
                    session['username'] = app.config['username']
                    return redirect(url_for('home'))
                else:
                    error = 'Invalid password'
            else:
                # Check if the username exists in the database
                query = 'SELECT * FROM users WHERE username = ?'
                user = query_db(query, [request.form['username']], one=True)
                if user:
                    # Check if the passwords are identical
                    testPassword = bcrypt.check_password_hash(user['password'], request.form['password'])
                    if testPassword:
                        session['logged_in'] = True
                        session['id'] = user['id']
                        session['username'] = request.form['username']
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
        if testUsername or form['username'] == 'admin':
            error.append("Sorry, this username is not available. Please choose another one")
        # Check if the passwords are identical
        if request.form['password'] != request.form['password2']:
            error.append("Please enter the same password in both of the password fields")
        # Check if the email address is already used
        query = 'SELECT * FROM users WHERE email = ?'
        testEmail = query_db(query, [request.form['email']], one=True)
        if testEmail:
            errorEmail = "The email address provided is already used by the user " + testEmail['username']
            error.append(errorEmail)
        # Insert in the database if everything is ok
        if not error:
            # Hash the password
            password = bcrypt.generate_password_hash(request.form['password'])
            # Insert
            db = get_db()
            db.cursor().execute('INSERT INTO users (username, password, email) VALUES (?,?,?)', [request.form['username'], password, request.form['email']])
            db.commit()
            flash('You were successfully registered. Try to log in!')
            return render_template('login.html')
        return render_template('register.html', form=form, error=error)
    return render_template('register.html')

@app.route('/profile')
def profile():
    # Retrieve user information
    query = 'SELECT * FROM users WHERE id = ?'
    user = query_db(query, [session['id']], one=True)
    if not user:
        flash("This user doesn't exist")
        return redirect(url_for('home'))
    return render_template('profile.html', user=user)

@app.route('/manage_quizzes')
def manage_quizzes():
    # List of all the quizzes
    query = 'SELECT * FROM quiz ORDER BY level ASC'
    quiz = query_db(query)
    return render_template('manage_quizzes.html', quiz=quiz)

@app.route('/add_quiz', methods=['GET', 'POST'])
def add_quiz():
    if request.method == 'POST':
        error = None
        # Check if the fields are not empty
        if request.form['title'] != '' and request.form['level'] != '':
            # Insert the quiz into DB
            db = get_db()
            db.cursor().execute('INSERT INTO quiz (title, level) VALUES (?,?)', [request.form['title'], request.form['level']])
            db.commit()
            flash('The quiz was added.')
            return redirect(url_for('manage_quizzes'))
        else:
            error = "You must enter a title and a level."
            return render_template('add_quiz.html', error=error, form=request.form)
    return render_template('add_quiz.html')

@app.route('/edit_quiz/<int:id>', method=['GET', 'POST'])
def edit_quiz(id):
    if request.method == "POST":
        error = None
        # Check if the fields are not empty
        if request.form['title'] != '' and request.form['level'] != '':
            # Update the quiz into DB
            db = get_db()
            db.cursor().execute('UPDATE quiz SET title = ?, level = ?', [request.form['title'], request.form['level']])
            db.commit()
            flash('The quiz was updated.')
            return redirect(url_for('manage_quizzes'))
        else:
            error = "You must enter a title and a level."
            return render_template('edit_quiz.html', error=error, form=request.form)
    # Quiz information
    query = 'SELECT * FROM quiz WHERE id = ?'
    quiz = query_db(query, [id], one=True)
    return render_template('edit_quiz.html', quiz=quiz)

@app.route('/remove_quiz/<int:id>')
def delete(id):
    if not session.get('logged_in') and session['username'] == "admin":
        abort(401)
    cur = g.db.cursor()
    # Remove in the DB
    cur.execute('DELETE FROM quiz WHERE id = ?', [id])
    # Remove all the questions and answers
    questions = query_db('SELECT id FROM questions WHERE quiz_id = ?', [id])
    if questions:
        for q in questions:
            cur.execute('DELETE FROM answers WHERE question_id = ?', [q.id])
            cur.execute('DELETE FROM questions WHERE id = ?', [q.id])
    g.db.commit()
    flash('The quiz was successfully removed.')
    return redirect(url_for('manage_quizzes'))

@app.route('/add_question')
def add_question():
    # Security
    if session['logged_in'] and session['username'] == app.config['username']:
        return render_template('add_question.html')
    else:
        flash("You are not allowed to show this content.")
        return redirect(url_for('home'))

@app.route('/rules')
def rules():
    return render_template('rules.html')

@app.route('/basic_vocabulary')
def basic_voc():
    return render_template('basic_voc.html')

@app.route('/build_sentence')
def build_sentence():
    return render_template('build_sentence.html')

@app.route('/quiz_beginners')
def quiz_beginners():
    return render_template('quiz_beginners.html')

if __name__ == '__main__':
    init(app)
    app.run(
        host = app.config['ip_address'],
        port = int(app.config['port'])
    )
