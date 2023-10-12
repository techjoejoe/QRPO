import os
from flask import Blueprint, render_template, redirect, url_for, flash, request, send_from_directory, jsonify
from flask_login import login_user, login_required, current_user
from functools import wraps
from qr_points_app import db, bcrypt, socketio
from qr_points_app.forms.user_forms import AdminRegistrationForm
from qr_points_app.models.user import User, ScannedQR, QRCode, Group, Checkin
from qr_points_app.qr_utils import generate_qr
from flask_socketio import SocketIO, emit
from datetime import datetime
from flask import flash, redirect, url_for
from qr_points_app.routes.user_routes import update_leaderboard


admin = Blueprint('admin', __name__)

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not current_user.is_admin:
            flash('You do not have permission to access this page.', 'error')
            return redirect(url_for('users.login'))
        return f(*args, **kwargs)
    return decorated_function

@admin.route("/admin_register", methods=['GET', 'POST'])
def admin_register():
    if current_user.is_authenticated and current_user.is_admin:
        return redirect(url_for('admin.admin_dashboard'))
    
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        existing_user = User.query.filter_by(email=form.email.data).first()
        if existing_user:
            flash('Email already exists. Please choose a different one.', 'error')
            return redirect(url_for('admin.admin_register'))

        if form.admin_secret.data.lower() != "approved":
            flash('Invalid admin secret.', 'error')
            return redirect(url_for('admin.admin_register'))
        
        hashed_password = bcrypt.generate_password_hash(form.password.data).decode('utf-8')
        user = User(first_name=form.first_name.data, last_name=form.last_name.data, email=form.email.data, password=hashed_password, is_admin=True)
        db.session.add(user)
        db.session.commit()
        flash('Your admin account has been created!', 'success')
        login_user(user)
        return redirect(url_for('admin.admin_dashboard'))
    return render_template('admin_register.html', title='Admin Register', form=form)

@admin.route('/admin_dashboard', methods=['GET', 'POST'])
@login_required
@admin_required
def admin_dashboard():
    if request.method == 'POST':
        group_code = request.form.get('group_code')
        if Group.query.filter_by(code=group_code).first():
            flash('Group code already exists. Choose another.', 'error')
        else:
            new_group = Group(code=group_code)
            db.session.add(new_group)
            db.session.commit()
            flash('Group created successfully.', 'success')

    qrcodes = QRCode.query.all()
    groups = Group.query.order_by(Group.id.desc()).all()
    leaderboards = {group.id: User.query.filter_by(group_id=group.id).order_by(User.points.desc()).all() for group in groups}
    return render_template('admin_dashboard.html', title='Admin Dashboard', qrcodes=qrcodes, groups=groups, leaderboards=leaderboards)

@admin.route('/qr_code/<int:qr_id>')
@login_required
def view_qr_code(qr_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'admin')
        return redirect(url_for('users.login'))
    return send_from_directory(os.path.join(os.getcwd(), 'qr_points_app/static/qr_codes'), f'qr_{qr_id}.png')

@admin.route('/delete_qr/<int:qr_id>', methods=['POST'])
@login_required
def delete_qr(qr_id):
    if not current_user.is_admin:
        flash('You do not have permission to perform this action.', 'admin')
        return redirect(url_for('admin.admin_dashboard'))

    qr_code = QRCode.query.get_or_404(qr_id)
    group_id = qr_code.group_id  # Get the group_id from the QRCode object
    try:
        os.remove(os.path.join(os.getcwd(), 'qr_points_app/static/qr_codes', f'qr_{qr_id}.png'))
        db.session.delete(qr_code)
        db.session.commit()
        flash('QR Code deleted successfully!', 'admin')
    except Exception as e:
        flash(f'An error occurred: {e}', 'admin')

    return redirect(url_for('admin.manage_qr_codes', group_id=group_id))  # Specify the group_id here

@admin.route('/create_group', methods=['GET', 'POST'])
@login_required
def create_group():
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'admin')
        return redirect(url_for('users.login'))

    if request.method == 'POST':
        group_code = request.form.get('group_code').lower()
        if Group.query.filter_by(code=group_code).first():
            flash('Group code already exists. Choose another.', 'admin')
            return redirect(url_for('admin.admin_dashboard'))

        new_group = Group(code=group_code)
        db.session.add(new_group)
        db.session.commit()
        flash('Group created successfully.', 'admin')
        
    # Always redirect to admin_dashboard, regardless of whether it's a GET or POST request
    return redirect(url_for('admin.admin_dashboard'))

@admin.route('/delete_group/<int:group_id>', methods=['POST'])
@login_required
def delete_group(group_id):
    if not current_user.is_admin:
        flash('You do not have permission to access this page.', 'admin')
        return redirect(url_for('users.login'))
    
    group = Group.query.get_or_404(group_id)  # Correctly getting the group first
    try:
        # Disassociate users from the group
        users_in_group = User.query.filter_by(group_id=group_id).all()
        for user in users_in_group:
            user.group_id = None
            user.points = 0  # Reset points to zero
            
        # Delete each QR code associated with the group along with its image
        for qr_code in group.qrcodes:
            os.remove(os.path.join(os.getcwd(), 'qr_points_app/static/qr_codes', f'qr_{qr_code.id}.png'))
            db.session.delete(qr_code)  # This will also delete associated ScannedQR due to cascade delete
        
        # Finally, delete the group
        db.session.delete(group)
        db.session.commit()

        socketio.emit('clear_leaderboard', room=str(group_id))
        
        flash('Group deleted successfully.', 'admin')
    except Exception as e:
        db.session.rollback()
        flash(f'Error occurred: {e}', 'admin')
    return redirect(url_for('admin.admin_dashboard'))

@admin.route('/select_group/<int:group_id>', methods=['POST'])
@login_required
def select_group(group_id):
    if not current_user.is_admin:
        return jsonify(error='You do not have permission to access this page.'), 403
    try:
        users_in_group = User.query.filter_by(group_id=group_id).order_by(User.points.desc()).all()
        leaderboard_list = [{'username': user.username, 'points': user.points} for user in users_in_group]
        return jsonify(leaderboard=leaderboard_list)
    except Exception as e:
        return jsonify(error=str(e)), 500

@admin.route('/manage_qr_codes/<int:group_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def manage_qr_codes(group_id):
    group = Group.query.get_or_404(group_id)
    qr_codes_list = [
        {'id': qr.id, 'description': qr.description, 'value': qr.value, 'created_by': qr.created_by.username if qr.created_by else 'N/A'}
        for qr in group.qrcodes
    ]

    if request.method == 'POST':
        value = request.form.get('value')
        description = request.form.get('description')

        if not value or not description:
            flash('Value and description are required.', 'error')
            return render_template('manage_qr_codes.html', title='Manage QR Codes', group=group, qr_codes=qr_codes_list)

        try:
            qr_code = QRCode(value=value, description=description, group_id=group_id, is_checkin=True)  # Set the flag when creating a check-in QR code
            qr_code = QRCode(value=value, description=description, group_id=group_id)
            db.session.add(qr_code)
            db.session.commit()

            unique_url = url_for('users.handle_qr_scan', qr_code_id=qr_code.id, _external=True)
            filename = f"qr_{qr_code.id}.png"
            generate_qr(unique_url, os.path.join('qr_points_app/static/qr_codes', filename))

            flash('QR Code generated successfully!', 'success')
            # Re-fetch the qr_codes_list after adding a new one
            qr_codes_list = [
    {'id': qr.id, 'description': qr.description, 'value': qr.value, 'created_by': qr.created_by.username if qr.created_by else 'N/A'}
    for qr in group.qrcodes
]
        except Exception as e:
            flash('An error occurred while processing your request. Please try again later.', 'error')
        print(qr_codes_list)
    return render_template('manage_qr_codes.html', title='Manage QR Codes', group=group, qr_codes_list=qr_codes_list, test_var="Hello World")

@admin.route('/show_leaderboard/<int:group_id>', methods=['GET'])
@login_required
@admin_required
def show_leaderboard(group_id):
    group = Group.query.get_or_404(group_id)
    users_in_group = User.query.filter_by(group_id=group_id).order_by(User.points.desc()).all()
    return render_template('show_leaderboard.html', title='show Leaderboard', group=group, users=users_in_group)

@admin.route('/view_learners/<int:group_id>', methods=['GET'])
@login_required
@admin_required
def view_learners(group_id):
    # Your code to fetch and display learners for the group with id `group_id`
    group = Group.query.get_or_404(group_id)
    users = User.query.filter_by(group_id=group.id).all()
    return render_template('view_learners.html', group=group, users=users)

@admin.route('/add_point/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def add_point(user_id):
    user = User.query.get(user_id)  # Query the user from the database
    if user:
        user.points += 1  # Increment the user's points by 1
        db.session.commit()  # Commit the changes to the database
        
        # Call the update_leaderboard function to send updated leaderboard
        update_leaderboard(user.group_id)  # Update leaderboard for the user's group

        flash('Point added successfully!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('admin.view_learners', group_id=user.group_id))  # Redirect back to the view_learners page of the user's group

@admin.route('/subtract_point/<int:user_id>', methods=['POST'])
@login_required
@admin_required
def subtract_point(user_id):
    user = User.query.get(user_id)  # Query the user from the database
    if user:
        user.points -= 1  # Decrement the user's points by 1
        db.session.commit()  # Commit the changes to the database
        
        # Call the update_leaderboard function to send updated leaderboard
        update_leaderboard(user.group_id)  # Update leaderboard for the user's group

        flash('Point subtracted successfully!', 'success')
    else:
        flash('User not found!', 'error')
    return redirect(url_for('admin.view_learners', group_id=user.group_id))  # Redirect back to the view_learners page of the user's group


@admin.route('/checkin/<int:group_id>', methods=['GET', 'POST'])
@login_required
@admin_required
def checkin(group_id):
    group = Group.query.get_or_404(group_id)
    if request.method == 'POST':
        today = datetime.utcnow().date()
        existing_qr = QRCode.query.filter_by(group_id=group_id, date_created=today).first()
        if existing_qr:
            db.session.delete(existing_qr)
        # Create a new check-in QR code and associate it with the group
        description = f"Daily Check-In {today}"
        new_checkin_qr = QRCode(value=10, description=description, is_checkin=True, group_id=group_id, date_created=today)
        db.session.add(new_checkin_qr)
        db.session.commit()
        
        unique_url = url_for('users.handle_qr_scan', qr_code_id=new_checkin_qr.id, _external=True)
        filename = f"qr_{new_checkin_qr.id}.png"
        generate_qr(unique_url, os.path.join('qr_points_app/static/qr_codes', filename))
        
        flash('New Check-in QR Code Generated!', 'success')
        
       # This part will be executed for both GET requests and POST requests after processing them
    today = datetime.utcnow().date()
    qr_code = QRCode.query.filter_by(group_id=group_id, date_created=today).first()

    all_users_in_group = User.query.filter_by(group_id=group_id).all()
    from sqlalchemy import cast, Date
    
    all_checked_in_users = Checkin.query.filter(
        Checkin.qr_code_id == qr_code.id, 
        cast(Checkin.timestamp, Date) == today
    ).all() if qr_code else []
    
    all_checked_in = len(all_checked_in_users) == len(all_users_in_group)
    
    return render_template('checkin.html', qr_code=qr_code, group=group, all_checked_in=all_checked_in)

