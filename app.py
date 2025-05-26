from flask import Flask, render_template, request, redirect, url_for, session, jsonify, send_file, Response, flash
from flask_mysqldb import MySQL
from io import BytesIO
import qrcode
import MySQLdb.cursors
import cv2
import numpy as np
from cv2 import QRCodeDetector
import secrets
import hashlib
import bcrypt
from datetime import datetime, timedelta

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

# MySQL configuration
app.config['MYSQL_HOST'] = 'localhost'
app.config['MYSQL_USER'] = 'root'
app.config['MYSQL_PASSWORD'] = ''
app.config['MYSQL_DB'] = 'parking_db'
app.config['MYSQL_CURSORCLASS'] = 'DictCursor'

mysql = MySQL(app)

# Helper functions
def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password_hash(hashed_password, user_password):
    return bcrypt.checkpw(user_password.encode(), hashed_password.encode())

@app.route('/contact')
def contact():
    return render_template('contact.html')

# Routes
@app.route('/')
def home():
    if 'user_id' in session:
        if session.get('role') == 'admin':
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        
        if not username or not password:
            flash('Please fill all fields', 'error')
            return redirect(url_for('login'))
        
        cursor = mysql.connection.cursor()
        try:
            cursor.execute('''
                (SELECT id, password, 'user' as role, is_approved, username FROM users WHERE username = %s)
                UNION
                (SELECT id, password, 'admin' as role, 1 as is_approved, username FROM admins WHERE username = %s)
            ''', (username, username))
            
            account = cursor.fetchone()
            
            if account:
                if account['role'] == 'user':
                    if not account['is_approved']:
                        flash('Account not approved yet', 'error')
                    elif check_password_hash(account['password'], password):
                        session['user_id'] = account['id']
                        session['role'] = 'user'
                        session['username'] = account['username']
                        flash('Login successful', 'success')
                        return redirect(url_for('dashboard'))
                
                elif account['role'] == 'admin':
                    if account['password'] == hashlib.md5(password.encode()).hexdigest():
                        session['admin_id'] = account['id']
                        session['role'] = 'admin'
                        session['username'] = account['username']
                        flash('Admin login successful', 'success')
                        return redirect(url_for('admin_dashboard'))
            
            flash('Invalid username or password', 'error')
        
        except Exception as e:
            flash('Database error occurred', 'error')
        finally:
            cursor.close()
    
    return render_template('login.html')

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out', 'info')
    return redirect(url_for('login'))

@app.route('/dashboard')
def dashboard():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor()
    try:
        # Get user's QR code with additional info
        cursor.execute('''
            SELECT 
                q.id,
                q.code,
                q.is_active,
                q.expires_at,
                p.location_name,
                DATEDIFF(q.expires_at, NOW()) as expires_in_days
            FROM qr_codes q
            LEFT JOIN parking_lots p ON q.parking_lot_id = p.id
            WHERE q.user_id = %s
            ORDER BY q.requested_at DESC
            LIMIT 1
        ''', (session['user_id'],))
        qr_code = cursor.fetchone()
        
        return render_template('dashboard.html', qr_code=qr_code)
    except Exception as e:
        flash('Error loading dashboard', 'error')
        return render_template('dashboard.html')
    finally:
        cursor.close()

@app.route('/admin/dashboard')
def admin_dashboard():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor()
    try:
        # Get pending user approvals
        cursor.execute('SELECT id, username, full_name, email FROM users WHERE is_approved = 0')
        pending_users = cursor.fetchall()
        
        # Get pending QR code requests
        cursor.execute('''
            SELECT q.id, u.username, q.requested_at 
            FROM qr_codes q
            JOIN users u ON q.user_id = u.id
            WHERE q.is_active = FALSE AND q.approved_at IS NULL
        ''')
        pending_qrs = cursor.fetchall()
        
        # Get parking lot status
        cursor.execute('SELECT id, location_name, total_slots, available_slots FROM parking_lots')
        parking_lots = cursor.fetchall()
        
        # Get recent activity
        cursor.execute('''
            SELECT pl.id, u.username, q.code, pl.status, pl.scanned_at, p.location_name
            FROM parking_logs pl
            JOIN qr_codes q ON pl.qr_code_id = q.id
            JOIN users u ON q.user_id = u.id
            JOIN parking_lots p ON q.parking_lot_id = p.id
            ORDER BY pl.scanned_at DESC LIMIT 20
        ''')
        parking_logs = cursor.fetchall()
        
        return render_template('admin_dashboard.html',
                            pending_users=pending_users,
                            pending_qrs=pending_qrs,
                            parking_lots=parking_lots,
                            parking_logs=parking_logs)
    except Exception as e:
        flash('Error loading dashboard data', 'error')
        return render_template('admin_dashboard.html')
    finally:
        cursor.close()

@app.route('/admin/decline_user/<int:user_id>', methods=['POST'])
def decline_user(user_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor()
    try:
        # Delete user and their QR codes
        cursor.execute('DELETE FROM qr_codes WHERE user_id = %s', (user_id,))
        cursor.execute('DELETE FROM users WHERE id = %s', (user_id,))
        mysql.connection.commit()
        flash('User registration declined and removed', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash('Error declining user', 'error')
    finally:
        cursor.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/decline_qr/<int:qr_id>', methods=['POST'])
def decline_qr(qr_id):
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('DELETE FROM qr_codes WHERE id = %s', (qr_id,))
        mysql.connection.commit()
        flash('QR request declined', 'success')
    except Exception as e:
        mysql.connection.rollback()
        flash('Error declining QR request', 'error')
    finally:
        cursor.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/approve_user', methods=['POST'])
def approve_user():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    user_id = request.form.get('user_id')
    if not user_id:
        flash('No user specified', 'error')
        return redirect(url_for('admin_dashboard'))
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('UPDATE users SET is_approved = 1 WHERE id = %s', (user_id,))
        
        cursor.execute('SELECT id FROM parking_lots WHERE available_slots > 0 LIMIT 1')
        parking_lot = cursor.fetchone()
        
        if parking_lot:
            qr_code = f"QR{secrets.token_hex(8).upper()}"
            expires_at = datetime.now() + timedelta(days=2)
            
            cursor.execute('''
                INSERT INTO qr_codes 
                (user_id, parking_lot_id, code, expires_at, is_active)
                VALUES (%s, %s, %s, %s, 1)
            ''', (user_id, parking_lot['id'], qr_code, expires_at))
            
            cursor.execute('''
                UPDATE parking_lots 
                SET available_slots = available_slots - 1 
                WHERE id = %s
            ''', (parking_lot['id'],))
            
            mysql.connection.commit()
            flash('User approved and QR code generated', 'success')
        else:
            flash('No available parking slots', 'error')
    
    except Exception as e:
        mysql.connection.rollback()
        flash('Error approving user', 'error')
    finally:
        cursor.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/generate_qr')
def generate_qr():
    code = request.args.get('code')
    if not code:
        return "No code provided", 400
    
    try:
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=10,
            border=4,
        )
        qr.add_data(code)
        qr.make(fit=True)
        
        img = qr.make_image(fill_color="black", back_color="white")
        img_io = BytesIO()
        img.save(img_io, 'PNG')
        img_io.seek(0)
        
        if request.args.get('download'):
            return send_file(
                img_io,
                mimetype='image/png',
                as_attachment=True,
                download_name=f'parking_qr_{code}.png'
            )
        
        return send_file(img_io, mimetype='image/png')
    except Exception as e:
        return "Error generating QR code", 500

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        # Get form data
        full_name = request.form.get('full_name')
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        confirm_password = request.form.get('confirm_password')

        # Validate inputs
        if not all([full_name, username, email, password, confirm_password]):
            flash('Please fill all fields', 'error')
            return redirect(url_for('register'))

        if password != confirm_password:
            flash('Passwords do not match', 'error')
            return redirect(url_for('register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters', 'error')
            return redirect(url_for('register'))

        cursor = mysql.connection.cursor()
        try:
            # Check if username or email already exists
            cursor.execute(
                'SELECT id FROM users WHERE username = %s OR email = %s', 
                (username, email)
            )
            if cursor.fetchone():
                flash('Username or email already exists', 'error')
                return redirect(url_for('register'))

            # Hash password
            hashed_password = hash_password(password)

            # Insert new user (not approved by default)
            cursor.execute('''
                INSERT INTO users (full_name, username, email, password, is_approved)
                VALUES (%s, %s, %s, %s, 0)
            ''', (full_name, username, email, hashed_password))
            
            mysql.connection.commit()
            flash('Registration successful! Please wait for admin approval.', 'success')
            return redirect(url_for('register_success'))
        
        except Exception as e:
            mysql.connection.rollback()
            flash('Registration failed. Please try again.', 'error')
            return redirect(url_for('register'))
        
        finally:
            cursor.close()
    
    return render_template('register.html')

@app.route('/register/success')
def register_success():
    return render_template('register_success.html')

@app.route('/scanner')
def scanner():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    return render_template('scanner.html')

@app.route('/video_feed')
def video_feed():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    return Response(gen_frames(), mimetype='multipart/x-mixed-replace; boundary=frame')

@app.route('/process_scan', methods=['POST'])
def process_scan():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return jsonify({'success': False, 'message': 'Unauthorized'}), 401
    
    qr_code = request.json.get('code')
    if not qr_code:
        return jsonify({'success': False, 'message': 'No code provided'}), 400
    
    cursor = mysql.connection.cursor()
    try:
        cursor.execute('''
            SELECT q.id, q.user_id, q.parking_lot_id, q.is_active, q.expires_at,
                   u.full_name, p.location_name
            FROM qr_codes q
            JOIN users u ON q.user_id = u.id
            JOIN parking_lots p ON q.parking_lot_id = p.id
            WHERE q.code = %s
        ''', (qr_code,))
        qr_data = cursor.fetchone()
        
        if not qr_data:
            return jsonify({'success': False, 'message': 'Invalid QR code'}), 404
        
        if not qr_data['is_active'] or qr_data['expires_at'] < datetime.now():
            return jsonify({'success': False, 'message': 'QR code expired or inactive'}), 400
        
        cursor.execute('''
            SELECT status FROM parking_logs 
            WHERE qr_code_id = %s 
            ORDER BY scanned_at DESC LIMIT 1
        ''', (qr_data['id'],))
        last_log = cursor.fetchone()
        
        new_status = 'EXIT' if last_log and last_log['status'] == 'ENTRY' else 'ENTRY'
        
        cursor.execute('''
            INSERT INTO parking_logs (qr_code_id, status)
            VALUES (%s, %s)
        ''', (qr_data['id'], new_status))
        
        mysql.connection.commit()
        
        return jsonify({
            'success': True,
            'status': new_status,
            'user': qr_data['full_name'],
            'location': qr_data['location_name']
        })
    except Exception as e:
        mysql.connection.rollback()
        return jsonify({'success': False, 'message': 'Database error'}), 500
    finally:
        cursor.close()

def gen_frames():
    camera = cv2.VideoCapture(0)
    qr_detector = QRCodeDetector()
    
    while True:
        success, frame = camera.read()
        if not success:
            break
        
        # Detect QR codes
        retval, decoded_info, points, straight_qrcode = qr_detector.detectAndDecodeMulti(frame)
        
        if retval and len(decoded_info) > 0:
            for i, (info, pts) in enumerate(zip(decoded_info, points)):
                if info:  # Only draw if we found a QR code with content
                    pts = pts.astype(int)
                    n = len(pts)
                    for j in range(n):
                        cv2.line(frame, tuple(pts[j]), tuple(pts[(j+1) % n]), (0, 255, 0), 3)
        
        ret, buffer = cv2.imencode('.jpg', frame)
        frame = buffer.tobytes()
        yield (b'--frame\r\n'
               b'Content-Type: image/jpeg\r\n\r\n' + frame + b'\r\n')
        
@app.route('/request_qr', methods=['POST'])
def request_qr():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    
    try:
        # Check if user already has an active or pending QR request
        cursor.execute('''
            SELECT id FROM qr_codes 
            WHERE user_id = %s AND (is_active = TRUE OR approved_at IS NULL)
        ''', (user_id,))
        
        if cursor.fetchone():
            flash('You already have an active or pending QR request', 'error')
            return redirect(url_for('dashboard'))
        
        # Create new QR request
        cursor.execute('''
            INSERT INTO qr_codes (user_id, code, requested_at)
            VALUES (%s, %s, NOW())
        ''', (user_id, f"REQ_{secrets.token_hex(8)}"))
        
        mysql.connection.commit()
        flash('QR code request submitted for admin approval', 'success')
    
    except Exception as e:
        mysql.connection.rollback()
        flash('Error submitting QR request', 'error')
    
    finally:
        cursor.close()
    
    return redirect(url_for('dashboard'))

@app.route('/admin/approve_qr', methods=['POST'])
def approve_qr():
    if 'admin_id' not in session or session.get('role') != 'admin':
        return redirect(url_for('login'))
    
    qr_id = request.form.get('qr_id')
    days_valid = int(request.form.get('days_valid', 7))  # Default 7 days
    
    if not qr_id:
        flash('No QR code specified', 'error')
        return redirect(url_for('admin_dashboard'))
    
    cursor = mysql.connection.cursor()
    
    try:
        # Get the QR request
        cursor.execute('''
            SELECT user_id FROM qr_codes 
            WHERE id = %s AND is_active = FALSE
        ''', (qr_id,))
        qr_data = cursor.fetchone()
        
        if not qr_data:
            flash('Invalid QR request', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Find available parking lot
        cursor.execute('''
            SELECT id FROM parking_lots 
            WHERE available_slots > 0 
            LIMIT 1
        ''')
        parking_lot = cursor.fetchone()
        
        if not parking_lot:
            flash('No available parking slots', 'error')
            return redirect(url_for('admin_dashboard'))
        
        # Generate new QR code
        new_code = f"QR_{secrets.token_hex(8)}"
        expires_at = datetime.now() + timedelta(days=days_valid)
        
        # Approve the QR code
        cursor.execute('''
            UPDATE qr_codes 
            SET 
                code = %s,
                parking_lot_id = %s,
                expires_at = %s,
                is_active = TRUE,
                approved_at = NOW()
            WHERE id = %s
        ''', (new_code, parking_lot['id'], expires_at, qr_id))
        
        # Decrease available slots
        cursor.execute('''
            UPDATE parking_lots 
            SET available_slots = available_slots - 1 
            WHERE id = %s
        ''', (parking_lot['id'],))
        
        mysql.connection.commit()
        flash('QR code approved successfully', 'success')
    
    except Exception as e:
        mysql.connection.rollback()
        flash('Error approving QR code', 'error')
    
    finally:
        cursor.close()
    
    return redirect(url_for('admin_dashboard'))

@app.route('/renew_qr', methods=['POST'])
def renew_qr():
    if 'user_id' not in session or session.get('role') != 'user':
        return redirect(url_for('login'))
    
    user_id = session['user_id']
    cursor = mysql.connection.cursor()
    
    try:
        # Check if user has an expiring QR code
        cursor.execute('''
            SELECT id, parking_lot_id 
            FROM qr_codes 
            WHERE user_id = %s 
            AND is_active = TRUE 
            AND expires_at < DATE_ADD(NOW(), INTERVAL 3 DAY)
        ''', (user_id,))
        
        qr_data = cursor.fetchone()
        
        if not qr_data:
            flash('No QR code needs renewal', 'info')
            return redirect(url_for('dashboard'))
        
        # Create renewal request
        cursor.execute('''
            INSERT INTO qr_codes (user_id, code, parking_lot_id, requested_at)
            VALUES (%s, %s, %s, NOW())
        ''', (user_id, f"RENEW_{secrets.token_hex(8)}", qr_data['parking_lot_id']))
        
        mysql.connection.commit()
        flash('QR code renewal requested', 'success')
    
    except Exception as e:
        mysql.connection.rollback()
        flash('Error requesting QR renewal', 'error')
    
    finally:
        cursor.close()
    
    return redirect(url_for('dashboard'))



if __name__ == '__main__':
    app.run(debug=True)