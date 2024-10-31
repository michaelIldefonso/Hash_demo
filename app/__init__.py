from flask import Flask

def create_app():
    app = Flask(__name__)
    
    # Load configurations
    app.config.from_object('config.Config')

    # Register blueprints, if any
    from .routes import main
    app.register_blueprint(main)

    return app
