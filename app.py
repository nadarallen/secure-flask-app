from flask import Flask
from config import Config
from models import db, bcrypt, User
from flask_login import LoginManager

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    db.init_app(app)
    bcrypt.init_app(app)
    
    login_manager = LoginManager(app)
    login_manager.login_view = 'main.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Register blueprints
    from routes import main
    app.register_blueprint(main)

    # Create tables if they don't exist
    with app.app_context():
        db.create_all()

    return app

app = create_app()

if __name__ == '__main__':
    app.run(debug=True)
