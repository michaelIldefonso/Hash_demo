# app/__init__.py
from flask import Flask

def create_app():
    app = Flask(__name__, static_folder='static')  # Set static_folder here
    print("Static folder path:", app.static_folder)
    
    # Load configurations
    app.config.from_object('config.Config')

    # Register blueprints, if any
    from .routes import main
    app.register_blueprint(main)

    return app

# Create the app instance
app = create_app()
