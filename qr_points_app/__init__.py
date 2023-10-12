import os
from flask import Flask, render_template, redirect, url_for
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_login import LoginManager
from flask_socketio import SocketIO
from flask_migrate import Migrate
from datetime import timedelta  # Import timedelta here


app = Flask(__name__, static_folder=os.path.abspath('qr_points_app/static'))

app.config['SECRET_KEY'] = os.environ.get("approved", "default_key")
app.debug = True

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(days=3650)

base_dir = os.path.abspath(os.path.dirname(__file__))
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///' + os.path.join(base_dir, '..', 'instance', 'site.db')
db = SQLAlchemy(app)  # Only one instance of SQLAlchemy is needed

print("Static Folder Path: ", os.path.abspath(app.static_folder))

# Now initialize migrate after db is initialized
migrate = Migrate(app, db)

bcrypt = Bcrypt(app)
login_manager = LoginManager(app)
login_manager.login_view = 'users.login'
login_manager.login_message_category = 'info'
login_manager.login_message = None  # Disable the default login message

socketio = SocketIO(app, cors_allowed_origins="*")

@app.route('/')
def index():
    return redirect(url_for('users.login'))
# Print the rules after registering the blueprints
for rule in app.url_map.iter_rules():
    print(rule)

@app.errorhandler(404)
def page_not_found(e):
    return render_template('404.html'), 404

from qr_points_app.routes.user_routes import users
from qr_points_app.routes.admin_routes import admin

app.register_blueprint(users)
app.register_blueprint(admin)
