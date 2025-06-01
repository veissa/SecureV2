from app import app, db, User
from utils import generate_rsa_keys, save_rsa_keys

with app.app_context():
    users = User.query.all()
    for user in users:
        private_key, public_key = generate_rsa_keys()
        save_rsa_keys(user.id, private_key, public_key)
    print(f"Clés RSA régénérées pour {len(users)} utilisateurs.") 