# ==============================
# === IMPORTS AND CONFIGURATION ===
# ==============================

from flask import Blueprint, render_template, redirect, url_for, flash, request, session, send_from_directory, jsonify
from flask_login import login_user, logout_user, login_required, current_user
from qr_points_app import db, bcrypt, socketio
from qr_points_app.forms.user_forms import LoginForm, RegistrationForm, JoinGroupForm
from qr_points_app.models.user import User, ScannedQR, QRCode, Group, Checkin
from flask_socketio import SocketIO, emit, join_room, leave_room
from sqlalchemy import cast, Date
from werkzeug.utils import secure_filename
import os, re, time
import pyheif
from PIL import Image, Exiftags
from datetime import datetime, timedelta

users = Blueprint('users', __name__)
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), 'static', 'user_avatar')
current_question_buzzer = {}

@users.route("/check_upload_folder")
def check_upload_folder():
    return UPLOAD_FOLDER

# ==============================
# === UTILITY FUNCTIONS ===
# ==============================

def heic_to_jpg(heic_path, output_path):  
    heif_file = pyheif.read(heic_path)
    image = Image.frombytes(heif_file.mode, heif_file.size, heif_file.data, "raw", heif_file.mode, heif_file.stride)
    image.save(output_path, "JPEG")

def get_next_avatar_number(directory):  
    filenames = os.listdir(directory)
    pattern = r"avataruser(\d+)\.jpg"
    numbers = [int(re.search(pattern, filename).group(1)) for filename in filenames if re.search(pattern, filename)]
    return max(numbers, default=0) + 1

def update_leaderboard():
    if current_user.group_id:
        users_in_group = User.query.filter_by(group_id=current_user.group_id).order_by(User.points.desc()).all()
        leaderboard_data = [{"user_id": user.id, "username": user.first_name + ' ' + user.last_name, "points": user.points} for user in users_in_group]
        return {'leaderboard': leaderboard_data}
    else:
        return {'leaderboard': []}
        
def correct_image_orientation(image):
    try:
        for orientation in ExifTags.TAGS.keys():
            if ExifTags.TAGS[orientation] == 'Orientation':
                break
        exif = image._getexif()
        if exif[orientation] == 3:
            image = image.rotate(180, expand=True)
        elif exif[orientation] == 6:
            image = image.rotate(270, expand=True)
        elif exif[orientation] == 8:
            image = image.rotate(90, expand=True)
    except (AttributeError, KeyError, TypeError, IndexError):
        # No EXIF information or no orientation info
        pass
    return image

# ==============================
# === SOCKET.IO EVENT HANDLERS ===
# ==============================
@socketio.on('test_event')
def handle_test_event(data):
    print('Received test_event with data:', data)

room_clients = {}
@socketio.on('join')
def on_join(data):
    room = data['room']
    join_room(room)

    # Add the user's sid to the room_clients dictionary
    if room not in room_clients:
        room_clients[room] = []
    room_clients[room].append(request.sid)

    print(f"User {request.sid} joined room {room}")

    emit('join_response', {'success': True})


@socketio.on('leave')
def on_leave(data):
    room = data['room']
    leave_room(room)

    # Remove the user's sid from the room_clients dictionary
    if room in room_clients:
        room_clients[room].remove(request.sid)

    print(f"User {request.sid} left room {room}")

@socketio.on('start_question')
def start_question():  
    socketio.emit('enable_buzzer', broadcast=True)

@socketio.on('buzz_in')
def buzz_in():  
    user_id = current_user.id
    timestamp = datetime.utcnow()
    if not current_question_buzzer:
        current_question_buzzer['user_id'] = user_id
        current_question_buzzer['timestamp'] = timestamp
        socketio.emit('user_buzzed_first', {'user_id': user_id}, broadcast=True)


@socketio.on('buzz_in')
def buzz_in(data):  
    user_id = data['user_id']
    if not current_question_buzzer:
        current_question_buzzer['user_id'] = user_id
        current_question_buzzer['timestamp'] = datetime.utcnow()
        socketio.emit('user_buzzed_first', {'user_id': user_id}, broadcast=True)

# ==============================
# === ROUTE HANDLERS ===
# ==============================

@users.route("/login", methods=['GET', 'POST'])
def login():  
    if current_user.is_authenticated:
        print("User is already logged in. Redirecting to user dashboard...")
        return redirect(url_for('users.user_dashboard'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user and bcrypt.check_password_hash(user.password, form.password.data):
            login_user(user, remember=form.remember.data)
            session.permanent = True  
            session.pop('_flashes', None)  # Clear all flash messages
            if current_user.is_admin:
                return redirect(url_for('admin.admin_dashboard'))
            return redirect(url_for('users.user_dashboard'))
        else:
            flash('Login Unsuccessful. Please register if you have not already.', 'danger')
    return render_template('login.html', title='Login', form=form)

@users.route("/user_register", methods=['GET', 'POST'])
def register():  
    if current_user.is_authenticated:
        return redirect(url_for('users.join_group'))
    form = RegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('User already exists. Login instead!', 'info')
            return redirect(url_for('users.login'))
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_password)
        if form.photo.data:
            next_number = get_next_avatar_number(UPLOAD_FOLDER)
            output_filename = f"avataruser{next_number}.jpg"
            output_path = os.path.join(UPLOAD_FOLDER, output_filename)
            user.user_avatar = 'user_avatar/' + output_filename
            if form.photo.data.filename.lower().endswith('.heic'):
                temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{next_number}.heic")
                form.photo.data.save(temp_path)
                heic_to_jpg(temp_path, output_path)
                os.remove(temp_path)
            else:
                image = Image.open(form.photo.data)
                image = correct_image_orientation(image)  # Correct the orientation based on EXIF
                image.save(output_path, "JPEG")
        else:
            user.user_avatar = user.set_default_avatar()
        db.session.add(user)
        try:
            db.session.commit()
            login_user(user)
            return redirect(url_for('users.user_dashboard'))
        except Exception as e:
            db.session.rollback()  
            flash('Error occurred: {}'.format(str(e)), 'danger')
            return redirect(url_for('users.register'))
    return render_template('user_register.html', title='Register', form=form)

@users.route("/edit_profile", methods=['POST'])
def edit_profile():  
    first_name = request.form.get('first_name')
    last_name = request.form.get('last_name')
    email = request.form.get('email')
    photo = request.files.get('photo')
    current_user.first_name = first_name
    current_user.last_name = last_name
    current_user.email = email
    if photo:
        if current_user.user_avatar and 'default' not in current_user.user_avatar:
            old_path = os.path.join(os.getcwd(), current_user.user_avatar)
            if os.path.exists(old_path):
                os.remove(old_path)
        next_number = get_next_avatar_number(UPLOAD_FOLDER)
        output_filename = f"avataruser{next_number}.jpg"
        output_path = os.path.join(UPLOAD_FOLDER, output_filename)
        current_user.user_avatar = ' user_avatar/' + output_filename
        if photo.filename.lower().endswith('.heic'):
            temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{next_number}.heic")
            photo.save(temp_path)
            heic_to_jpg(temp_path, output_path)
            os.remove(temp_path)
        else:
            image = Image.open(photo)
            image = correct_image_orientation(image)  # Correct the orientation based on EXIF
            image.save(output_path, "JPEG")
    try:
        db.session.commit()
        flash('Profile updated successfully', 'success')
    except Exception as e:
        db.session.rollback()  
        flash('Error occurred: {}'.format(str(e)), 'danger')
    return redirect(url_for('users.user_dashboard'))

@users.route('/view_avatar/<int:user_id>')
def view_avatar(user_id):  
    user = User.query.get_or_404(user_id)
    
    # Strip out the "static/" prefix from user.user_avatar
    avatar_path = user.user_avatar.replace('static/', '', 1)
    
    # Redirect to the static URL of the avatar
    return redirect(url_for('static', filename=avatar_path))


@users.route("/logout", methods=['GET', 'POST'])
def logout():  
    logout_user()
    return redirect(url_for('users.login'))

@users.route('/handle_qr_scan/<int:qr_code_id>', methods=['GET'])
@login_required
def handle_qr_scan(qr_code_id):
    qr_code = QRCode.query.get_or_404(qr_code_id)
    scanned_qr = ScannedQR.query.filter_by(user_id=current_user.id, qr_code_id=qr_code_id).first()

    if scanned_qr:
        if datetime.utcnow() - scanned_qr.last_scanned < timedelta(minutes=3):
            flash("You've recently scanned this QR code.", "warning")
        else:
            scanned_qr.last_scanned = datetime.utcnow()
            current_user.points += qr_code.value  # Update user points
            db.session.commit()
            flash(f"Successfully scanned {qr_code.description} for {qr_code.value} points!", "success")
    else:
        new_scan = ScannedQR(user_id=current_user.id, qr_code_id=qr_code_id, last_scanned=datetime.utcnow(), points_received=qr_code.value)
        db.session.add(new_scan)
        current_user.points += qr_code.value  # Update user points
        db.session.commit()
        flash(f"Successfully scanned {qr_code.description} for {qr_code.value} points!", "success")

    # Emit updated leaderboard after QR scan
    updated_leaderboard_data = get_sorted_leaderboard(current_user.group_id)
    socketio.emit('update_leaderboard', {'leaderboard': updated_leaderboard_data}, broadcast=True)

    return redirect(url_for('users.user_dashboard'))

def get_sorted_leaderboard(group_id):
    """Fetch and sort the leaderboard data for the given group ID."""
    users_in_group = User.query.filter_by(group_id=group_id).order_by(User.points.desc()).all()
    leaderboard_data = [{"user_id": user.id, "username": f"{user.first_name} {user.last_name}", "points": user.points} for user in users_in_group]
    return leaderboard_data

@users.route('/join_group', methods=['GET', 'POST'])
def join_group():  
    group_code = request.form.get('group_code')  # Assuming you're getting the group code from the form
    group = Group.query.filter(Group.code.ilike(group_code)).first()
    
    if group:
        current_user.group_id = group.id
        db.session.commit()
        socketio.emit('update_leaderboard', room=group.id)
        flash('Successfully joined the group!', 'success')
        return redirect(url_for('users.user_dashboard'))
    else:
        flash('Invalid group code!', 'danger')
        return redirect(url_for('users.join_group'))

    return render_template('join_group.html', form=form)

@users.route('/leave_group', methods=['POST', 'GET'])
def leave_group():  
    group_id_to_leave = current_user.group_id
    if group_id_to_leave:
        current_user.group_id = None
        current_user.points = 0  # Reset the user's points to zero
        db.session.commit()
        socketio.emit('update_leaderboard', room=group_id_to_leave)
        flash('Successfully left the group.', 'success')
        return redirect(url_for('users.user_dashboard'))
    else:
        flash('You are not part of any group.', 'warning')
        return redirect(url_for('users.join_group'))

@users.route("/user_dashboard", methods=['GET', 'POST'])
def user_dashboard():  
    if current_user.is_admin:
        return redirect(url_for('admin.admin_dashboard'))
    scanned_qrs = ScannedQR.query.filter_by(user_id=current_user.id).all()
    users_in_group = []
    group = None  
    first_user = None
    second_user = None
    third_user = None
    if current_user.group_id:
        group = Group.query.get(current_user.group_id)  
        users_in_group = User.query.filter_by(group_id=current_user.group_id).order_by(User.points.desc()).all()
        leaderboard_data = [{"user_id": user.id, "username": user.first_name + ' ' + user.last_name, "points": user.points} for user in users_in_group]
        socketio.emit('update_leaderboard', {'leaderboard': leaderboard_data}, room=str(current_user.group_id))
        if users_in_group:
            first_user = users_in_group[0]
            if len(users_in_group) > 1:
                second_user = users_in_group[1]
            if len(users_in_group) > 2:
                third_user = users_in_group[2]
    return render_template('user_dashboard.html', scanned_qrs=scanned_qrs, leaderboard=users_in_group, group=group, first_user=first_user, second_user=second_user, third_user=third_user)


@users.route("/buzz_in", methods=['POST'])
def buzz_in():  
    user_id = request.form.get('user_id')
    if user_id not in current_question_buzzer:
        current_question_buzzer.append(user_id)
        position = len(current_question_buzzer)
        socketio.emit('buzz_in_order_updated', {'buzz_in_order': current_question_buzzer}, broadcast=True)
        return jsonify(position=position, success=True)
    else:
        return jsonify(message="Already buzzed in", success=False)


# ==============================
# === LEADERBOARD FUNCTION ===
# ==============================

    
