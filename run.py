print("Starting the app...")

from qr_points_app import app, socketio

if __name__ == '__main__':
    print("Running the app with SocketIO...")
    socketio.run(app, debug=True)
