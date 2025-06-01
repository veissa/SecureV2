from app import app, db, User
from werkzeug.security import generate_password_hash
with app.app_context():
    # Create admin user
    if not User.query.filter_by(email="admin@example.com").first():
        user = User(email="admin@example.com", is_admin=True)
        user.password_hash = generate_password_hash("admin1234", method="pbkdf2:sha256")
        db.session.add(user)
        print("Admin user created!")
    else:
        print("Admin user already exists.")
    # Create regular user
    if not User.query.filter_by(email="user@example.com").first():
        user = User(email="user@example.com", is_admin=False)
        user.password_hash = generate_password_hash("user1234", method="pbkdf2:sha256")
        db.session.add(user)
        print("Regular user created!")
    else:
        print("Regular user already exists.")
    db.session.commit() 