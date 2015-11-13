import ConfigParser

from flask import Flask, request, session, redirect, url_for, abort, render_template, flash

app = Flask(__name__)

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

# ROUTING

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        if request.form['username'] != app.config['username']:
            error = 'Invalid username'
        elif request.form['password'] != app.config['password']:
            error = 'Invalid password'
        else:
            session['logged_in'] = True
            flash('You were logged in')
            return redirect(url_for('home'))
    return render_template('login.html', error=error)

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('You were logged out')
    return redirect(url_for('home'))


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    return render_template('register.html', error=error)



if __name__ == '__main__':
    init(app)
    app.run(
        host = app.config['ip_address'],
        port = int(app.config['port'])
    )