from flask import Blueprint, render_template, redirect, url_for, flash, request, session
from flask_login import login_user, logout_user, login_required, current_user
from qr_points_app import db, bcrypt, socketio
from qr_points_app.forms.user_forms import LoginForm, RegistrationForm, JoinGroupForm
from qr_points_app.models.user import User, ScannedQR, QRCode, Group, Checkin
from datetime import datetime, timedelta
from flask_socketio import emit, join_room, leave_room
from sqlalchemy import cast, Date
from werkzeug.utils import secure_filename
import os
from PIL import Image
import pyheif
import time

users = Blueprint('users', __name__)
UPLOAD_FOLDER = '/Users/joe/Documents/Anew_qr_points_app/qr_points_app/static/user_avatar'

def heic_to_jpg(heic_path, output_path):
    heif_file = pyheif.read(heic_path)
    image = Image.frombytes(
        heif_file.mode, 
        heif_file.size, 
        heif_file.data,
        "raw",
        heif_file.mode,
        heif_file.stride,
    )
    image.save(output_path, "JPEG")
current_question_buzzer = {}

@socketio.on('join_room')
def on_join(data):
    username = data['username']
    room = data['room']
    join_room(room)
    print(f"{username} has joined the room {room}")
    update_leaderboard(room)

@socketio.on('leave_room')
def on_leave(data):
    username = data['username']
    room = data['room']
    leave_room(room)
    print(f"{username} has left the room {room}")
    update_leaderboard(room)

@socketio.on('start_question')
def start_question():
    # Broadcast to all clients to enable their buzzers
    socketio.emit('enable_buzzer', broadcast=True)

@socketio.on('buzz_in')
def buzz_in():
    user_id = current_user.id
    # Record the time and user_id
    timestamp = datetime.utcnow()
    
    # Logic to determine if this user buzzed first
    if not current_question_buzzer:
        current_question_buzzer['user_id'] = user_id
        current_question_buzzer['timestamp'] = timestamp
        socketio.emit('user_buzzed_first', {'user_id': user_id}, broadcast=True)

def update_leaderboard(group_id):
    print(f"update_leaderboard called with group_id: {group_id}")  # Debugging print statement
    if not group_id:
        print("update_leaderboard exited early due to None group_id")  # Debugging print statement
        return  # Return early if group_id is None
    
    leaderboard_data = []
    users_in_group = User.query.filter_by(group_id=group_id, is_admin=False).all()
    for user in users_in_group:
        leaderboard_data.append({"user_id": user.id, "username": user.first_name + ' ' + user.last_name, "points": user.points})

    # Sort the leaderboard_data based on points, in descending order.
    sorted_leaderboard_data = sorted(leaderboard_data, key=lambda x: x["points"], reverse=True)

    # Now that the data is sorted, print it
    print(f"Sending leaderboard data: {sorted_leaderboard_data}")
    
    socketio.emit('update_leaderboard', {'leaderboard': sorted_leaderboard_data}, room=str(group_id))




from flask import send_from_directory

@socketio.on('update_points')
def update_points():
    # Assuming points are passed from the frontend
    points = request.json.get('points', 10) # Default to 10 for demonstration
    current_user.points += points
    db.session.commit()

    # Get the rank of the current user after updating points
    rank_subquery = db.session.query(
        User.id,
        User.points,
        db.func.rank().over(order_by=db.desc(User.points)).label('rank')
    ).subquery()

    new_rank = db.session.query(rank_subquery.c.rank).filter_by(id=current_user.id).scalar()

    # Emitting only the changes to the client
    emit_data = {
        'user_id': current_user.id,
        'new_points': current_user.points,
        'new_rank': new_rank
    }
    socketio.emit('update_leaderboard', emit_data, broadcast=True)







@users.route("/login", methods=['GET', 'POST'])
def login():
    # Check if the user is already logged in
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


import re

def get_next_avatar_number(directory):
    # List all filenames in the directory
    filenames = os.listdir(directory)
    
    # Use a regex pattern to find all avatar numbers
    pattern = r"avataruser(\d+)\.jpg"
    numbers = [int(re.search(pattern, filename).group(1)) for filename in filenames if re.search(pattern, filename)]
    
    # Return the next number (or 1 if no avatars exist yet)
    return max(numbers, default=0) + 1

@users.route("/user_register", methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('users.join_group'))
    form = RegistrationForm()
    if form.validate_on_submit():
        # Check if a user with the given email already exists
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('User already exists. Login instead!', 'info')
            return redirect(url_for('users.login'))
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_password)
        
        # Handle the uploaded profile image
        if form.photo.data:
            next_number = get_next_avatar_number(UPLOAD_FOLDER)
            output_filename = f"avataruser{next_number}.jpg"
            output_path = os.path.join(UPLOAD_FOLDER, output_filename)
            user.user_avatar = 'static/user_avatar/' + output_filename

            # If the file is a HEIC, convert it to JPG
            if form.photo.data.filename.lower().endswith('.heic'):
                temp_path = os.path.join(UPLOAD_FOLDER, f"temp_{next_number}.heic")
                form.photo.data.save(temp_path)
                heic_to_jpg(temp_path, output_path)
                os.remove(temp_path)
            else:
                # Directly save the file as JPG (even if it's a JPEG, PNG, etc.)
                image = Image.open(form.photo.data)
                image.save(output_path, "JPEG")
        else:
            user.user_avatar = user.set_default_avatar()

        db.session.add(user)
        try:
            db.session.commit()
            login_user(user)
            return redirect(url_for('users.user_dashboard'))
        except Exception as e:
            db.session.rollback()  # Rollback the session to the clean state
            flash('Error occurred: {}'.format(str(e)), 'danger')
            return redirect(url_for('users.register'))

    return render_template('user_register.html', title='Register', form=form)

@users.route('/view_avatar/<int:user_id>')
def view_avatar(user_id):
    user = User.query.get_or_404(user_id)
    return send_from_directory(UPLOAD_FOLDER, os.path.basename(user.user_avatar))


@users.route("/logout", methods=['GET', 'POST'])
def logout():
    logout_user()
    return redirect(url_for('users.login'))



@users.route('/join_group', methods=['GET', 'POST'])
@login_required
def join_group():
    form = JoinGroupForm()  # This ensures the form object is available for both GET and POST requests

    if request.method == 'POST':
        group_code = request.form.get('group_code')
        
        # Check if group_code is a valid string
        if not group_code or not isinstance(group_code, str):
            flash('Invalid group code!', 'danger')
            return redirect(url_for('users.user_dashboard'))

        group = Group.query.filter(Group.code.ilike(group_code)).first()
        if group:
            # Update leaderboard for the group user is about to join
            update_leaderboard(group.id)
            
            current_user.group_id = group.id
            db.session.commit()
            
            flash('Successfully joined the group!', 'success')
            return redirect(url_for('users.user_dashboard'))
        else:
            flash('Invalid group code!', 'danger')
            update_leaderboard(current_user.group_id)    
            return redirect(url_for('users.user_dashboard'))
    return render_template('join_group.html', form=form)




@users.route('/leave_group', methods=['POST', 'GET'])
@login_required
def leave_group():
    group_id = current_user.group_id
    if group_id:
        # Don't directly leave the room here.
        # Instead, notify the client-side to initiate leaving the room.
        current_user.group_id = None  # User leaves the group first
        db.session.commit()

        # Update leaderboard after the user has left the group
        update_leaderboard(group_id)
        
        flash('Successfully left the group.', 'success')
        return redirect(url_for('users.user_dashboard'))
    else:
        flash('You are not part of any group.', 'warning')
        return redirect(url_for('users.join_group'))




@users.route("/user_dashboard", methods=['GET', 'POST'])
@login_required
def user_dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin.admin_dashboard'))
    
    scanned_qrs = ScannedQR.query.filter_by(user_id=current_user.id).all()
    users_in_group = []
    group = None  # Initialize group to None
    first_user = None
    second_user = None
    third_user = None
    
    if current_user.group_id:
        group = Group.query.get(current_user.group_id)  # Fetch the group object
        users_in_group = User.query.filter_by(group_id=current_user.group_id).order_by(User.points.desc()).all()
        
        # Emitting the entire leaderboard to the client when they visit the dashboard
        leaderboard_data = [{"user_id": user.id, "username": user.first_name + ' ' + user.last_name, "points": user.points} for user in users_in_group]
        socketio.emit('initial_leaderboard', {'leaderboard': leaderboard_data}, room=str(current_user.group_id))
        
        if users_in_group:
            first_user = users_in_group[0]
            if len(users_in_group) > 1:
                second_user = users_in_group[1]
            if len(users_in_group) > 2:
                third_user = users_in_group[2]
                
    return render_template('user_dashboard.html', scanned_qrs=scanned_qrs, leaderboard=users_in_group, group=group, first_user=first_user, second_user=second_user, third_user=third_user)




@users.route('/handle_qr_scan/<int:qr_code_id>', methods=['GET'])
@login_required
def handle_qr_scan(qr_code_id):
    qr_code = QRCode.query.get_or_404(qr_code_id)
    scanned_qr = ScannedQR.query.filter_by(user_id=current_user.id, qr_code_id=qr_code_id).first()
    
    if scanned_qr:
        if datetime.utcnow() - scanned_qr.last_scanned < timedelta(minutes=3):
            flash("You've recently scanned this QR code.", "warning")
            return redirect(url_for('users.user_dashboard'))
        
        scanned_qr.last_scanned = datetime.utcnow()
        scanned_qr.points_received = qr_code.value
        db.session.commit()
        current_user.points += qr_code.value
        db.session.commit()
        socketio.emit('update_leaderboard', {'user_id': current_user.id, 'points': current_user.points})

    else:
        new_scan = ScannedQR(user_id=current_user.id, qr_code_id=qr_code_id, points_received=qr_code.value, last_scanned=datetime.utcnow())
        current_user.points += qr_code.value
        db.session.add(new_scan)
        db.session.commit()

    flash(f"Successfully scanned {qr_code.description} for {qr_code.value} points!", "success")
    update_leaderboard(current_user.group_id)  # Passed current_user.group_id as a parameter
    return redirect(url_for('users.user_dashboard'))


@users.route('/handle_checkin_qr_scan/<int:qr_code_id>', methods=['GET', 'POST'])
@login_required
def handle_checkin_qr_scan(qr_code_id):
    qr_code = QRCode.query.get_or_404(qr_code_id)
    if not qr_code.is_checkin:
        flash('Invalid QR Code', 'error')
        return redirect(url_for('users.user_dashboard'))
    
    now = datetime.utcnow()
    today = now.date()
    
    checkin = Checkin.query.filter_by(user_id=current_user.id, qr_code_id=qr_code_id, timestamp=cast(Checkin.timestamp, Date)==today).first()
    if checkin:
        flash('You already scanned for today', 'error')
        return redirect(url_for('users.user_dashboard'))
    else:
        socketio.emit('user_checked_in', {'username': current_user.your_name, 'timestamp': str(datetime.utcnow())}, namespace='/checkin')
        current_user.points += 10
        new_checkin = Checkin(user_id=current_user.id, qr_code_id=qr_code_id, timestamp=now)
        db.session.add(new_checkin)
        db.session.commit()
        update_leaderboard(current_user.group_id)  # Update leaderboard if needed, with the correct group_id
    
    flash('Successfully scanned. 10 points have been added to your score!', 'success')
    return redirect(url_for('users.user_dashboard'))

@socketio.on('buzz_in')
def buzz_in(data):
    user_id = data['user_id']
    # Logic to determine if this user buzzed first
    if not current_question_buzzer:
        current_question_buzzer['user_id'] = user_id
        current_question_buzzer['timestamp'] = datetime.utcnow()
        socketio.emit('user_buzzed_first', {'user_id': user_id}, broadcast=True)


@users.route("/buzz_in", methods=['POST'])
def buzz_in():
    user_id = request.form.get('user_id')
    
    # If user hasn't buzzed in yet for this question
    if user_id not in buzz_in_order:
        buzz_in_order.append(user_id)
        position = len(buzz_in_order)
        
        # Notify all clients of the new buzz-in order
        socketio.emit('buzz_in_order_updated', {'buzz_in_order': buzz_in_order}, broadcast=True)
        
        return jsonify(position=position, success=True)
    else:
        return jsonify(message="Already buzzed in", success=False)


@users.route("/get_top_three_users", methods=['GET'])
@login_required
def get_top_three_users():
    group_id = current_user.group_id
    if not group_id:
        return jsonify(error="User not in any group"), 400

    top_users = User.query.filter_by(group_id=group_id).order_by(User.points.desc()).limit(3).all()
    result = {}
    if len(top_users) > 0:
        result['first_user'] = {'id': top_users[0].id}
    if len(top_users) > 1:
        result['second_user'] = {'id': top_users[1].id}
    if len(top_users) > 2:
        result['third_user'] = {'id': top_users[2].id}
    
    return jsonify(result)