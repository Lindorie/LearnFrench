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

    except:
        print ('Could not read config from: '), config_location

# ROUTING

@app.route('/')
def home():
    return render_template('home.html')

if __name__ == '__main__':
    init(app)
    app.run(
        host = app.config['ip_address'],
        port = int(app.config['port'])
    )