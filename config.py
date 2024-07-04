# config.py

class Config:
    SECRET_KEY = 'fallbacksecret'
    SQLALCHEMY_DATABASE_URI = 'sqlite:///events.db'
    UPLOAD_FOLDER = 'uploads/'
    MOC_SERVER_URL = 'https://moc-server.com/api/events'
    # Add other global configurations here

class DevelopmentConfig(Config):
    DEBUG = True
    # Development-specific configurations

class ProductionConfig(Config):
    DEBUG = False
    # Production-specific configurations
