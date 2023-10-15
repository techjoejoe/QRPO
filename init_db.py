# init_db.py

from qr_points_app import app, db

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        print("Database initialized!")
