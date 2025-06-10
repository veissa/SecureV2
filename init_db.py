from app import app, db
from flask_migrate import Migrate, init, migrate, upgrade

# Initialize migrations
migrate = Migrate(app, db)

with app.app_context():
    # Create migrations directory and initialize
    init()
    
    # Create initial migration
    migrate()
    
    # Apply migrations
    upgrade()
    
    print("Database initialized successfully!") 