from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
from flask_wtf.csrf import CSRFProtect
from forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm, OtpForm
import re
from flask_mail import Mail, Message
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Using non-interactive backend
import matplotlib.pylab as plt
import seaborn as sns
import os
import socket
from datetime import datetime, timedelta
from decimal import Decimal
import random 
import string
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import pytz
from google import genai
from flask import send_file
import zipfile
import io
import logging
import requests

load_dotenv()

# Configure logging to output to console (Render logs)
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[logging.StreamHandler()]
)

app = Flask(__name__)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# Production configuration for PostgreSQL
if os.environ.get('RENDER'):
    db_url = os.environ.get('DATABASE_URL', '')
    if db_url.startswith('postgres://'):
        db_url = db_url.replace('postgres://', 'postgresql://', 1)
    app.config['SQLALCHEMY_DATABASE_URI'] = db_url
    mail_server = os.environ.get('MAIL_SERVER', 'smtp.gmail.com')
    mail_port = int(os.environ.get('MAIL_PORT', 465))
    use_ssl = os.environ.get('MAIL_USE_SSL', 'true').lower() == 'true'
    use_tls = os.environ.get('MAIL_USE_TLS', 'false').lower() == 'true'
    mail_timeout = int(os.environ.get('MAIL_TIMEOUT', 10))
    app.config['MAIL_SERVER'] = mail_server
    app.config['MAIL_PORT'] = mail_port
    app.config['MAIL_USE_SSL'] = use_ssl
    app.config['MAIL_USE_TLS'] = use_tls
    app.config['MAIL_TIMEOUT'] = mail_timeout
    app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
    app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')
else:
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost/wealthwisenew'
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 1025
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USE_SSL'] = False
    app.config['MAIL_TIMEOUT'] = 5
    app.config['MAIL_USERNAME'] = None
    app.config['MAIL_PASSWORD'] = None
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@wealthwise.com'

socket.setdefaulttimeout(app.config.get('MAIL_TIMEOUT', 10))

app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'WealthWise')
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)
app.config['TESTING'] = False
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_FAIL_SILENTLY'] = False
app.config['WTF_CSRF_ENABLED'] = True
app.config['SESSION_COOKIE_SECURE'] = True  # Required for HTTPS
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['WTF_CSRF_TIME_LIMIT'] = None  # No time limit for CSRF tokens

enc = Bcrypt(app)
mail = Mail(app)

nepal_tz = pytz.timezone('Asia/Kathmandu')

import resend

def send_email(to_email, subject, html_content):
    """Send email using Resend API"""
    resend_api_key = os.environ.get('RESEND_API_KEY')
    from_email = os.environ.get('EMAIL_USER')

    if not resend_api_key or not from_email:
        logging.error("RESEND_API_KEY or EMAIL_USER environment variables not set.")
        return False

    # Use Resend on Render environment
    if os.environ.get('RENDER'):
        try:
            logging.info(f"Attempting to send email via Resend to {to_email}")
            
            resend.api_key = resend_api_key
            
            params = {
                "from": f"WealthWise <{from_email}>",
                "to": [to_email],
                "subject": subject,
                "html": html_content,
            }
            
            email = resend.Emails.send(params)
            
            # The resend library raises an exception on failure.
            # If it returns, it was successful.
            logging.info(f"✓ Resend email sent successfully to {to_email}. Email ID: {email['id']}")
            return True

        except Exception as e:
            logging.error(f"Resend email exception: {type(e).__name__} - {str(e)}", exc_info=True)
            return False
    else:
        # Fallback to Flask-Mail for local development
        try:
            msg = Message(subject, recipients=[to_email])
            msg.html = html_content
            mail.send(msg)
            logging.info(f"Flask-Mail email sent to {to_email}")
            return True
        except Exception as e:
            logging.error(f"Flask-Mail email failed: {str(e)}")
            return False

def get_db_connection():
    if os.environ.get('RENDER'):
        db_url = os.environ.get('DATABASE_URL')
        if db_url and db_url.startswith('postgres://'):
            db_url = db_url.replace('postgres://', 'postgresql://', 1)
        conn = psycopg2.connect(db_url)
    else:
        conn = psycopg2.connect(
            host="localhost",
            database="wealthwisenew",
            user="postgres",
            password="root"
        )
    return conn

def is_logged_in():
    return 'user_id' in session

def is_email(identifier):
    return re.match(r'^\S+@\S+\.\S+$', identifier)

def generate_otp(length=6):
    return ''.join(random.choices(string.digits, k=length))

def is_real_email(email):
    """Check if email is real and deliverable using AbstractAPI"""
    api_key = 'f66c8efc772d49509881fdf75dc1d78d'
    url = f"https://emailvalidation.abstractapi.com/v1/?api_key={api_key}&email={email}"
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            data = response.json()
            return data.get('deliverability') == 'DELIVERABLE'
        else:
            logging.warning(f"Email validation API failed with status {response.status_code}")
            return True
    except Exception as e:
        logging.error(f"Email validation error: {str(e)}")
        return True

#DEBUG SESSION
@app.route('/debug_session')
def debug_session():
    session_data = dict(session)
    session.clear()
    flash('Session cleared.', 'info')
    logging.info(f"Cleared session: {session_data}")
    return jsonify(session_data)

#HOME
@app.route('/')
def home():
    return redirect(url_for('login'))

#LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        input_data = form.email_or_phone.data.strip()
        pw = form.password.data
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            if 'reset_token' in session:
                reset_data = session['reset_token']
                if datetime.now(nepal_tz).timestamp() > reset_data['expires']:
                    session.pop('reset_token', None)
                    logging.info("Cleared expired reset_token")
                else:
                    flash('Please reset your password using the link sent to your email before logging in.', 'danger')
                    cursor.close()
                    conn.close()
                    return redirect(url_for('forgot_password'))
            if 'user_id' in session:
                flash('Another user is already logged in. Please log out first.', 'danger')
                cursor.close()
                conn.close()
                return redirect(url_for('logout'))
            if is_email(input_data):
                cursor.execute('SELECT * FROM users WHERE email = %s', (input_data,))
            else:
                phone = re.sub(r'^\+977', '', input_data).strip()
                cursor.execute('SELECT * FROM users WHERE phone_number = %s', (phone,))
            account = cursor.fetchone()
            if account:
                use_otp = account['use_otp'] if account['use_otp'] is not None else False
                stored_hashed_pw = account['password_hash']
                full_name = account['full_name']
                email = account['email']
                if enc.check_password_hash(stored_hashed_pw, pw):
                    if use_otp:
                        if 'otp_data' not in session or not session.get('otp_data'):
                            otp = generate_otp()
                            otp_expiry = (datetime.now(nepal_tz) + timedelta(minutes=5)).timestamp()
                            session['otp_data'] = {
                                'otp': otp,
                                'email': email,
                                'user_id': account['id'],
                                'full_name': full_name,
                                'expires': otp_expiry,
                                'attempts': 0,
                                'lockout_time': None
                            }
                            html_content = render_template("otp_email.html", full_name=full_name, otp=otp)
                            if send_email(email, "Your Wealthwise OTP", html_content):
                                flash("An OTP has been sent to your email.", 'info')
                                logging.info(f"OTP sent to {email}")
                            else:
                                logging.error(f"OTP email sending failed to {email}")
                                flash(f'Error sending OTP. Please try again.', 'danger')
                        cursor.close()
                        conn.close()
                        return redirect(url_for('verify_otp'))
                    else:
                        session['user_id'] = account['id']
                        session.pop('otp_data', None)
                        flash('Login Successful', 'success')
                        cursor.close()
                        conn.close()
                        return redirect(url_for('dashboard', user_id=account['id']))
                else:
                    flash('Invalid Password', 'danger')
            else:
                flash('User not registered or invalid credentials', 'danger')
            cursor.close()
            conn.close()
        except Exception as e:
            logging.error(f"Login error: {str(e)}")
            flash(f"Error occurred: {str(e)}", "danger")
            if 'conn' in locals():
                conn.rollback()
                conn.close()
    return render_template('login.html', form=form)

#RESENDOTP
@app.route('/resend_otp', methods=['GET'])
def resend_otp():
    otp_data = session.get('otp_data')
    if not otp_data:
        flash('No active OTP session found. Please log in again.', 'danger')
        return redirect(url_for('login'))
    if datetime.now(nepal_tz).timestamp() > otp_data['expires']:
        session.pop('otp_data', None)
        flash('OTP has expired. Please log in again to receive a new OTP.', 'danger')
        return redirect(url_for('login'))
    if otp_data.get('lockout_time') and datetime.now(nepal_tz).timestamp() < otp_data['lockout_time']:
        remaining_time = int(otp_data['lockout_time'] - datetime.now(nepal_tz).timestamp())
        flash(f'Too many invalid attempts. Please wait {remaining_time} seconds for a new OTP.', 'danger')
        return redirect(url_for('verify_otp'))
    otp = generate_otp()
    otp_expiry = (datetime.now(nepal_tz) + timedelta(minutes=5)).timestamp()
    otp_data.update({
        'otp': otp,
        'expires': otp_expiry,
        'attempts': 0,
        'lockout_time': None
    })
    session['otp_data'] = otp_data
    email = otp_data['email']
    full_name = otp_data['full_name']
    html_content = render_template("otp_email.html", full_name=full_name, otp=otp)
    if send_email(email, "Your Wealthwise OTP", html_content):
        flash('A new OTP has been sent to your email.', 'success')
        logging.info(f"Resent OTP to {email}")
    else:
        logging.error(f"Resend OTP email sending failed to {email}")
        flash(f'Error sending OTP. Please try again.', 'danger')
    return redirect(url_for('verify_otp'))

#VERIFYOTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    form = OtpForm()
    otp_data = session.get('otp_data')
    if not otp_data:
        flash('No OTP session found. Please login again.', 'danger')
        return redirect(url_for('login'))
    if datetime.now(nepal_tz).timestamp() > otp_data['expires']:
        session.pop('otp_data', None)
        flash('OTP has expired. Please login again to receive a new OTP.', 'danger')
        return redirect(url_for('login'))
    if otp_data.get('lockout_time') and datetime.now(nepal_tz).timestamp() < otp_data['lockout_time']:
        remaining_time = int(otp_data['lockout_time'] - datetime.now(nepal_tz).timestamp())
        flash(f'Too many invalid attempts. Please wait {remaining_time} seconds for a new OTP.', 'danger')
        return render_template('verify_otp.html', form=form)
    if form.validate_on_submit():
        user_otp = form.otp.data.strip()
        otp_data['attempts'] += 1
        session['otp_data'] = otp_data
        if user_otp == otp_data['otp']:
            session['user_id'] = otp_data['user_id']
            session.pop('otp_data', None)
            flash('Login Successful', 'success')
            return redirect(url_for('dashboard', user_id=otp_data['user_id']))
        else:
            if otp_data['attempts'] >= 5:
                otp_data['lockout_time'] = (datetime.now(nepal_tz) + timedelta(minutes=5)).timestamp()
                session['otp_data'] = otp_data
                flash('Too many invalid OTP attempts. A new OTP will be sent after 5 minutes.', 'danger')
            else:
                flash(f'Invalid OTP. Attempts remaining: {5 - otp_data["attempts"]}', 'danger')
    return render_template('verify_otp.html', form=form)

#FORGOTPASSWORD
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            if is_email(identifier):
                cursor.execute('SELECT * FROM users WHERE email = %s', (identifier,))
            else:
                phone = re.sub(r'^\+977', '', identifier).strip()
                cursor.execute('SELECT * FROM users WHERE phone_number = %s', (phone,))
            user = cursor.fetchone()
            if user:
                token = f"{user['id']}-{int(datetime.now(nepal_tz).timestamp())}"
                reset_url = url_for('reset_password', token=token, _external=True)
                session['reset_token'] = {
                    'token': token,
                    'email': user['email'],
                    'phone': user['phone_number'],
                    'expires': (datetime.now(nepal_tz) + timedelta(minutes=3)).timestamp()
                }
                html_content = render_template("password_reset_email.html", full_name=user['full_name'], reset_url=reset_url)
                if send_email(user['email'], "Password Reset Request", html_content):
                    flash('A password reset link has been sent to your email.', 'success')
                    logging.info(f"Password reset email sent to {user['email']}")
                else:
                    logging.error(f"Password reset email sending failed to {user['email']}")
                    flash(f'Error sending email. Please try again.', 'danger')
            else:
                flash('Email or phone number not found. Please register first.', 'danger')
                logging.warning(f"Identifier not found: {identifier}")
                cursor.close()
                conn.close()
                return redirect(url_for('registration'))
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        except Exception as e:
            logging.error(f"Forgot password error: {str(e)}")
            flash(f'Error occurred: {str(e)}', 'danger')
            if 'conn' in locals():
                conn.rollback()
                conn.close()
    return render_template('forgot_password.html', form=form)

#RESETPASSWORD
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    reset_data = session.get('reset_token')
    if not reset_data or reset_data['token'] != token or datetime.now(nepal_tz).timestamp() > reset_data['expires']:
        flash('Invalid or expired reset link.', 'danger')
        session.pop('reset_token', None)
        return redirect(url_for('forgot_password'))
    
    if is_logged_in():
        session.pop('user_id', None)
        flash('You have been logged out to reset your password.', 'info')
    form = ResetPasswordForm()
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT password_hash FROM users WHERE email = %s OR phone_number = %s', 
                       (reset_data['email'], reset_data['phone']))
        user = cursor.fetchone()
        if user and 'password_hash' in user:
            form.meta = {'current_password_hash': user['password_hash']}
        else:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('forgot_password'))
        if form.validate_on_submit():
            try:
                hashed_password = enc.generate_password_hash(form.new_password.data).decode('utf-8')
                cursor.execute('UPDATE users SET password_hash = %s WHERE email = %s OR phone_number = %s', 
                               (hashed_password, reset_data['email'], reset_data['phone']))
                conn.commit()
                session.pop('reset_token', None)
                flash('Your password has been reset successfully. Please log in.', 'success')
                logging.info(f"Password reset successful for {reset_data['email']}")
                cursor.close()
                conn.close()
                return redirect(url_for('login'))
            except Exception as e:
                logging.error(f"Reset password error: {str(e)}")
                flash(f'Error occurred: {str(e)}', 'danger')
                conn.rollback()
        cursor.close()
        conn.close()
    except Exception as e:
        logging.error(f"Reset password fetch error: {str(e)}")
        flash(f'Error fetching user data: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('forgot_password'))
    return render_template('reset_password.html', form=form, token=token)

#REGISTRATION
@app.route('/registration', methods=['GET', 'POST'])
def registration():
    form = RegistrationForm()
    if form.validate_on_submit():
        full_name = form.full_name.data
        email = form.email.data
        phone_num = form.phone_num.data  
        address = form.address.data
        pw = form.password.data
        
        if not is_real_email(email):
            flash("Please enter a real, deliverable email address.", "danger")
            return render_template('register.html', form=form)
        
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            cursor.execute('SELECT * FROM users WHERE phone_number=%s OR email=%s', (phone_num, email))
            account = cursor.fetchone()
            if account:
                if account['phone_number'] == phone_num:
                    flash('Phone Number Already Registered! Please use a new number.', 'danger')
                elif account['email'] == email:
                    flash('Email Already Registered! Please use a new email.', 'danger')
                cursor.close()
                conn.close()
                return redirect(url_for('registration'))
            else:
                hash_pw = enc.generate_password_hash(pw).decode('utf-8')
                cursor.execute('''
                    INSERT INTO users (full_name, email, phone_number, address, password_hash, use_otp)
                    VALUES (%s, %s, %s, %s, %s, %s)
                ''', (full_name, email, phone_num, address, hash_pw, False))
                conn.commit()
                html_content = render_template("welcome_mail.html", full_name=full_name)
                if send_email(email, "Welcome to WealthWise!", html_content):
                    logging.info(f"Welcome email sent to {email}")
                else:
                    logging.error(f"Welcome email sending failed to {email}")
                    flash('Registration successful, but failed to send welcome email.', 'warning')
                cursor.close()
                conn.close()
                flash('You Have Successfully Registered!', 'success')
                flash('Tip: You can enable Two-Factor Authentication (2FA) from your dashboard settings for extra security.', 'info')
                return redirect(url_for('login'))
        except psycopg2.IntegrityError as e:
            conn.rollback()
            if 'unique_phone_number' in str(e):
                flash('Phone Number Already Registered! Please use a new number.', 'danger')
            elif 'unique_email' in str(e):
                flash('Email Already Registered! Please use a new email.', 'danger')
            else:
                flash(f'Registration error: {str(e)}', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('registration'))
        except Exception as e:
            logging.error(f"Registration error: {str(e)}")
            flash(f'Error occurred: {str(e)}', 'danger')
            if 'conn' in locals():
                conn.rollback()
                conn.close()
    return render_template('register.html', form=form)

#LOGOUT
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'success')
    logging.info("User logged out, session cleared")
    return redirect(url_for('login'))

#DASHBOARD
@app.route('/dashboard/<int:user_id>')
def dashboard(user_id):
    if not is_logged_in() or session.get('user_id') != user_id:
        flash('Session mismatch or not logged in.', 'danger')
        return redirect(url_for('login'))
    
    if 'otp_data' in session:
        return redirect(url_for('verify_otp'))
    
    if request.args.get('flash_message'):
        flash(request.args.get('flash_message'), 'success')
    
    conn = None
    cursor = None
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        
        # Validate user exists
        cursor.execute("SELECT id, full_name, use_otp FROM users WHERE id = %s", (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found. Please re-register or contact support.', 'danger')
            session.clear()
            return redirect(url_for('registration'))
        
        # Ensure budget allocation exists
        cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
        allocation = cursor.fetchone()
        if not allocation:
            cursor.execute('''
                INSERT INTO budget_allocations 
                (user_id, needs_percent, wants_percent, savings_percent, total_budget)
                VALUES (%s, %s, %s, %s, %s)
            ''', (user_id, 50.00, 30.00, 20.00, 0.00))
            conn.commit()
            allocation = {'needs_percent': Decimal('50.00'), 'wants_percent': Decimal('30.00'), 'savings_percent': Decimal('20.00'), 'total_budget': Decimal('0.00')}
        
        current_time = datetime.now(nepal_tz)
        current_month = current_time.month
        current_year = current_time.year
        
        cursor.execute('''
            SELECT 
                COALESCE(SUM(CASE WHEN transaction_type = 'income' AND category != 'savings' THEN amount ELSE 0 END), 0) as monthly_income,
                COALESCE(SUM(CASE WHEN transaction_type = 'expense' AND category = 'needs' THEN amount ELSE 0 END), 0) as needs_spent,
                COALESCE(SUM(CASE WHEN transaction_type = 'expense' AND category = 'wants' THEN amount ELSE 0 END), 0) as wants_spent,
                COALESCE(SUM(CASE WHEN transaction_type = 'expense' AND category = 'savings' THEN amount ELSE 0 END), 0) as savings_made
            FROM transactions 
            WHERE user_id = %s 
            AND EXTRACT(MONTH FROM date AT TIME ZONE 'Asia/Kathmandu') = %s 
            AND EXTRACT(YEAR FROM date AT TIME ZONE 'Asia/Kathmandu') = %s
        ''', (user_id, current_month, current_year))
        
        monthly_data = cursor.fetchone() or {
            'monthly_income': Decimal('0'),
            'needs_spent': Decimal('0'),
            'wants_spent': Decimal('0'),
            'savings_made': Decimal('0')
        }
        
        # Convert to Decimal safely
        monthly_income = Decimal(str(monthly_data['monthly_income'] or '0'))
        needs_spent = Decimal(str(monthly_data['needs_spent'] or '0'))
        wants_spent = Decimal(str(monthly_data['wants_spent'] or '0'))
        savings_made = Decimal(str(monthly_data['savings_made'] or '0'))
        
        # Ensure allocation percentages are Decimal
        needs_percent = Decimal(str(allocation['needs_percent'] or '50.00'))
        wants_percent = Decimal(str(allocation['wants_percent'] or '30.00'))
        savings_percent = Decimal(str(allocation['savings_percent'] or '20.00'))
        
        # Calculate limits and targets
        needs_limit = (monthly_income * needs_percent) / 100
        wants_limit = (monthly_income * wants_percent) / 100
        savings_target = (monthly_income * savings_percent) / 100
        
        # Calculate remaining amounts
        needs_remaining = max(Decimal('0'), needs_limit - needs_spent)
        wants_remaining = max(Decimal('0'), wants_limit - wants_spent)
        savings_remaining = max(Decimal('0'), savings_target - savings_made)
        
        return render_template('dashboard.html',
                              user=user,
                              monthly_income=float(monthly_income),
                              needs_limit=float(needs_limit),
                              wants_limit=float(wants_limit),
                              savings_target=float(savings_target),
                              needs_spent=float(needs_spent),
                              wants_spent=float(wants_spent),
                              savings_made=float(savings_made),
                              needs_remaining=float(needs_remaining),
                              wants_remaining=float(wants_remaining),
                              savings_remaining=float(savings_remaining),
                              current_month_name=current_time.strftime('%B'),
                              current_year=current_year,
                              monthly_expenses=float(needs_spent + wants_spent),
                              nepal_tz=nepal_tz,
                              use_otp=user['use_otp'] if user['use_otp'] is not None else False)
                            
    except Exception as e:
        logging.error(f"Dashboard error for user_id {user_id}: {str(e)}, monthly_data={monthly_data}, allocation={allocation}", exc_info=True)
        flash(f'An error occurred while loading the dashboard: {str(e)}. Please try again.', 'danger')
        return redirect(url_for('login'))
        
    finally:
        if cursor:
            cursor.close()
        if conn:
            conn.close()

#CHATBOT
@app.route('/chatbot/<int:user_id>', methods=['GET', 'POST'])
@csrf.exempt
def chatbot(user_id):
    if not is_logged_in():
        flash('Please log in to access the chatbot.', 'danger')
        return redirect(url_for('login'))
    if session['user_id'] != user_id:
        flash('You are not authorized to access this chatbot.', 'danger')
        return redirect(url_for('logout'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        full_name = user['full_name']
        if not user:
            cursor.close()
            conn.close()
            return jsonify({'response': 'User not found.'}), 400
        cursor.execute('''SELECT transaction_type, category, SUM(amount) as total
                        FROM transactions
                        WHERE user_id=%s
                        GROUP BY transaction_type, category''', (user_id,))
        transactions = cursor.fetchall()
        total_income = Decimal('0.0')
        needs_spent = Decimal('0.0')
        wants_spent = Decimal('0.0')
        savings_saved = Decimal('0.0')
        for transaction in transactions:
            amount = transaction['total']
            transaction_type = transaction['transaction_type']
            category = transaction['category'].lower()
            if transaction_type == 'income':
                total_income += amount
                if category == 'savings':
                    savings_saved += amount
            elif transaction_type == 'expense':
                if category == 'needs':
                    needs_spent += amount
                elif category == 'wants':
                    wants_spent += amount
        financial_data = (
            f"Total Income: Rs {float(total_income):.2f}, "
            f"Needs Spent: Rs {float(needs_spent):.2f} (Budget: 50%), "
            f"Wants Spent: Rs {float(wants_spent):.2f} (Budget: 30%), "
            f"Savings: Rs {float(savings_saved):.2f} (Goal: 20%)"
        )
        cursor.close()
        conn.close()
        if request.method == 'POST':
            # Handle JSON request
            if request.is_json:
                data = request.get_json()
                user_message = data.get('message', '').strip()
                context = data.get('context', '').strip() or ""
            else:
                # Fallback to form data
                user_message = request.form.get('message', '').strip()
                context = request.form.get('context', '').strip() or ""
            
            if not user_message:
                return jsonify({'response': 'Please enter a message.'}), 400
            try:
                api_key = os.environ.get('GEMINI_API_KEY')
                if not api_key:
                    logging.error("GEMINI_API_KEY not found in environment variables.")
                    return jsonify({'response': 'Chatbot is not configured. Please contact support.'}), 500

                # Use the Client class from google.genai
                client = genai.Client(api_key=api_key)
                
                prompt = f"""
You are a financial advisor for WealthWise, a finance management, advising, and recommendation app for students in Nepal. Provide concise, accurate financial advice (under 100 words) in NPR, focusing on budgeting and differentiating needs vs. wants. 
Needs are essential expenses (e.g., rent, groceries, utilities); wants are non-essential (e.g., entertainment, dining out). 
The average income of Nepalese students is from around Rs 5000.00 to Rs 25000.00.
Use the user's financial data. Stay professional, avoid non-financial topics, and do not ask questions unless prompted. 
If the query is unclear, suggest asking about budgeting or expenses.

User's financial data: {financial_data}

Conversation history: {context}

Question: {user_message}

Answer:"""
                
                # Use the client to generate content
                response = client.models.generate_content(
                    model='gemini-1.5-flash',
                    contents=prompt,
                    config={
                        'safety_settings': [
                            {'category': 'HARM_CATEGORY_HARASSMENT', 'threshold': 'BLOCK_NONE'},
                            {'category': 'HARM_CATEGORY_HATE_SPEECH', 'threshold': 'BLOCK_NONE'},
                            {'category': 'HARM_CATEGORY_SEXUALLY_EXPLICIT', 'threshold': 'BLOCK_NONE'},
                            {'category': 'HARM_CATEGORY_DANGEROUS_CONTENT', 'threshold': 'BLOCK_NONE'},
                        ]
                    }
                )
                
                ai_response = response.text
                new_context = f"{context}\nUser: {user_message}\nAI: {ai_response}".strip()
                return jsonify({'response': ai_response, 'context': new_context})

            except Exception as ai_error:
                # Log the full error for better debugging
                logging.error(f"Gemini API error for user {user_id}: {str(ai_error)}", exc_info=True)
                # Provide a more user-friendly error message
                return jsonify({'response': 'Error: Unable to get a response from the AI assistant at the moment. Please try again later.'}), 500

        prefilled_question = request.args.get('question', '')
        return render_template('chatbot.html', user=user, full_name=full_name, prefilled_question=prefilled_question)
    except Exception as e:
        logging.error(f"Chatbot error: {str(e)} - User: {user_id}")
        if 'conn' in locals():
            conn.close()
        return jsonify({'response': f'Error: {str(e)}'}), 500

#ADDINCOME
@app.route('/add_income/<int:user_id>', methods=['GET', 'POST'])
def add_income(user_id):
    if not is_logged_in():
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    if session['user_id'] != user_id:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('logout'))
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        amount = request.form.get('amount')
        category = request.form.get('category')
        date_str = request.form.get('date')
        description = request.form.get('description')
        income_id = request.form.get('id')
        if not amount or not category or not date_str:
            flash('All fields are required.', 'danger')
        else:
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                current_time = datetime.now(nepal_tz).time()
                full_datetime = datetime.combine(date_obj.date(), current_time)
                if income_id:
                    cursor.execute(
                        "UPDATE transactions SET amount=%s, category=%s, date=%s, description=%s WHERE id=%s AND user_id=%s",
                        (Decimal(amount), category, full_datetime, description, income_id, user_id)
                    )
                    flash('Income updated successfully!', 'success')
                else:
                    cursor.execute(
                        "INSERT INTO transactions (user_id, transaction_type, category, amount, date, description) VALUES (%s, 'income', %s, %s, %s, %s)",
                        (user_id, category, Decimal(amount), full_datetime, description)
                    )
                    flash('Income added successfully!', 'success')
                conn.commit()
                cursor.close()
                conn.close()
                return redirect(url_for('add_income', user_id=user_id))
            except Exception as e:
                logging.error(f"Add income error: {str(e)}")
                flash(f'Error adding income: {str(e)}', 'danger')
    current_month = datetime.now(nepal_tz).month
    current_year = datetime.now(nepal_tz).year
    cursor.execute('''
        SELECT * FROM transactions 
        WHERE user_id=%s AND transaction_type='income' 
        AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s 
        ORDER BY date DESC LIMIT 5
    ''', (user_id, current_month, current_year))
    recent_incomes = cursor.fetchall()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.close()
    conn.close()
    return render_template('add_income.html', user=user, recent_incomes=recent_incomes, nepal_tz=nepal_tz)

#EDITINCOME
@app.route('/edit_income/<int:user_id>/<int:income_id>', methods=['GET'])
def edit_income(user_id, income_id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to edit income.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.execute("SELECT * FROM transactions WHERE id=%s AND user_id=%s AND transaction_type='income'", (income_id, user_id))
        income = cursor.fetchone()
        if not income:
            flash('Income not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('add_income', user_id=user_id))
        cursor.execute("SELECT * FROM transactions WHERE user_id=%s AND transaction_type='income' ORDER BY date DESC LIMIT 5", (user_id,))
        recent_incomes = cursor.fetchall()
        cursor.close()
        conn.close()
        today = datetime.now(nepal_tz).strftime('%Y-%m-%d')
        return render_template('add_income.html', user=user, today=today, recent_incomes=recent_incomes, income=income, nepal_tz=nepal_tz)
    except Exception as e:
        logging.error(f"Edit income error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('dashboard', user_id=user_id))

#DELETEINCOME
@app.route('/delete_income/<int:user_id>/<int:income_id>', methods=['POST'])
def delete_income(user_id, income_id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to delete income.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.execute("DELETE FROM transactions WHERE id=%s AND user_id=%s AND transaction_type='income'", (income_id, user_id))
        conn.commit()
        flash('Income deleted successfully!', 'success')
        cursor.close()
        conn.close()
        return redirect(url_for('add_income', user_id=user_id))
    except Exception as e:
        logging.error(f"Delete income error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('add_income', user_id=user_id))

#ADDEXPENSE
@app.route('/add_expense/<int:user_id>', methods=['GET', 'POST'])
def add_expense(user_id):
    if not is_logged_in():
        flash('Please log in to access this page.', 'danger')
        return redirect(url_for('login'))
    if session['user_id'] != user_id:
        flash('You are not authorized to access this page.', 'danger')
        return redirect(url_for('logout'))
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    if request.method == 'POST':
        amount = request.form.get('amount')
        category = request.form.get('category')
        date_str = request.form.get('date')
        description = request.form.get('description')
        expense_id = request.form.get('id')
        if not amount or not category or not date_str:
            flash('All fields are required.', 'danger')
        else:
            try:
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                current_time = datetime.now(nepal_tz).time()
                full_datetime = datetime.combine(date_obj.date(), current_time)
                if expense_id:
                    cursor.execute(
                        "UPDATE transactions SET amount=%s, category=%s, date=%s, description=%s WHERE id=%s AND user_id=%s",
                        (Decimal(amount), category, full_datetime, description, expense_id, user_id)
                    )
                    if category.lower() == 'savings':
                        flash('Savings updated successfully!', 'success')
                    else:
                        flash('Expense updated successfully!', 'success')
                else:
                    cursor.execute(
                        "INSERT INTO transactions (user_id, transaction_type, category, amount, date, description) VALUES (%s, 'expense', %s, %s, %s, %s)",
                        (user_id, category, Decimal(amount), full_datetime, description)
                    )
                    if category.lower() == 'savings':
                        flash('Savings added successfully!', 'success')
                    else:
                        flash('Expense added successfully!', 'success')
                conn.commit()
                if category.lower() in ['needs', 'wants']:
                    current_month = datetime.now(nepal_tz).month
                    current_year = datetime.now(nepal_tz).year
                    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                    user = cursor.fetchone()
                    cursor.execute('''
                        SELECT SUM(amount) as monthly_income 
                        FROM transactions 
                        WHERE user_id = %s AND transaction_type = 'income' AND category != 'savings'
                        AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                    ''', (user_id, current_month, current_year))
                    income_result = cursor.fetchone()
                    monthly_income = Decimal(str(income_result['monthly_income'] or '0'))
                    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
                    allocation = cursor.fetchone()
                    if allocation and monthly_income > 0:
                        if category.lower() == 'needs':
                            limit = (monthly_income * Decimal(str(allocation['needs_percent'] or '50.00'))) / 100
                            category_name = "Needs"
                        elif category.lower() == 'wants':
                            limit = (monthly_income * Decimal(str(allocation['wants_percent'] or '30.00'))) / 100
                            category_name = "Wants"
                        cursor.execute('''
                            SELECT SUM(amount) as spent 
                            FROM transactions 
                            WHERE user_id = %s AND transaction_type = 'expense' 
                            AND category = %s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                        ''', (user_id, category, current_month, current_year))
                        spent_result = cursor.fetchone()
                        current_spent = Decimal(str(spent_result['spent'] or '0'))
                        percentage_used = (current_spent / limit) * 100 if limit > 0 else 0
                        if current_spent > limit:
                            overage = current_spent - limit
                            flash(f'Budget Alert: You have exceeded your {category_name} budget by Rs {float(overage):.2f} this month. Warning Email has been sent', 'warning')
                            try:
                                msg = Message("Budget Warning - WealthWise", recipients=[user['email']])
                                msg.html = render_template("warning.html", 
                                                         full_name=user['full_name'],
                                                         category=category_name,
                                                         status="exceeded",
                                                         spent=float(current_spent),
                                                         limit=float(limit),
                                                         percent=percentage_used,
                                                         user_id=user_id)
                                mail.send(msg)
                                logging.info(f"Budget warning email sent to {user['email']}")
                            except Exception as email_error:
                                logging.error(f"Budget warning email sending failed: {str(email_error)}")
                        elif percentage_used >= 80:
                            remaining = limit - current_spent
                            flash(f'Budget Notice: You have Rs {float(remaining):.2f} remaining in your {category_name} budget this month. Warning Email has been sent', 'info')
                            try:
                                msg = Message("Budget Alert - WealthWise", recipients=[user['email']])
                                msg.html = render_template("warning.html", 
                                                         full_name=user['full_name'],
                                                         category=category_name,
                                                         status="is approaching",
                                                         spent=float(current_spent),
                                                         limit=float(limit),
                                                         percent=percentage_used,
                                                         user_id=user_id)
                                mail.send(msg)
                                logging.info(f"Budget alert email sent to {user['email']}")
                            except Exception as email_error:
                                logging.error(f"Budget alert email sending failed: {str(email_error)}")
                elif category.lower() == 'savings':
                    current_month = datetime.now(nepal_tz).month
                    current_year = datetime.now(nepal_tz).year
                    cursor.execute('''
                        SELECT SUM(amount) as monthly_income 
                        FROM transactions 
                        WHERE user_id = %s AND transaction_type = 'income' AND category != 'savings'
                        AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                    ''', (user_id, current_month, current_year))
                    income_result = cursor.fetchone()
                    monthly_income = Decimal(str(income_result['monthly_income'] or '0'))
                    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
                    allocation = cursor.fetchone()
                    if allocation and monthly_income > 0:
                        savings_target = (monthly_income * Decimal(str(allocation['savings_percent'] or '20.00'))) / 100
                        cursor.execute('''
                            SELECT SUM(amount) as saved 
                            FROM transactions 
                            WHERE user_id = %s AND transaction_type = 'expense' 
                            AND category = 'savings' AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                        ''', (user_id, current_month, current_year))
                        saved_result = cursor.fetchone()
                        current_saved = Decimal(str(saved_result['saved'] or '0'))
                        if current_saved >= savings_target:
                            flash(f'Great job! You have saved Rs {float(current_saved):.2f}, meeting your savings target of Rs {float(savings_target):.2f} this month.', 'success')
                        else:
                            remaining = savings_target - current_saved
                            flash(f'Savings Update: You have saved Rs {float(current_saved):.2f}. Aim to save Rs {float(remaining):.2f} more to meet your target of Rs {float(savings_target):.2f}.', 'info')
                cursor.close()
                conn.close()
                return redirect(url_for('add_expense', user_id=user_id))
            except Exception as e:
                logging.error(f"Add expense error: {str(e)}")
                flash(f'Error adding expense: {str(e)}', 'danger')
    current_month = datetime.now(nepal_tz).month
    current_year = datetime.now(nepal_tz).year
    cursor.execute('''
        SELECT * FROM transactions 
        WHERE user_id=%s AND transaction_type='expense' 
        AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s 
        ORDER BY date DESC LIMIT 5
    ''', (user_id, current_month, current_year))
    recent_expenses = cursor.fetchall()
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN transaction_type = 'income' AND category != 'savings' THEN amount ELSE 0 END) as monthly_income,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'needs' THEN amount ELSE 0 END) as needs_spent,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'wants' THEN amount ELSE 0 END) as wants_spent
        FROM transactions 
        WHERE user_id = %s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
    ''', (user_id, current_month, current_year))
    monthly_data = cursor.fetchone()
    monthly_income = Decimal(str(monthly_data['monthly_income'] or '0'))
    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
    allocation = cursor.fetchone()
    if allocation and monthly_income > 0:
        needs_limit = (monthly_income * Decimal(str(allocation['needs_percent'] or '50.00'))) / 100
        wants_limit = (monthly_income * Decimal(str(allocation['wants_percent'] or '30.00'))) / 100
    else:
        needs_limit = Decimal('0')
        wants_limit = Decimal('0')
    cursor.close()
    conn.close()
    return render_template('add_expense.html', 
                         user=user, 
                         recent_expenses=recent_expenses,
                         needs_spent=float(monthly_data['needs_spent'] or 0),
                         wants_spent=float(monthly_data['wants_spent'] or 0),
                         needs_limit=float(needs_limit),
                         wants_limit=float(wants_limit),
                         nepal_tz=nepal_tz)

#EDITEXPENSE
@app.route('/edit_expense/<int:user_id>/<int:id>', methods=['GET'])
def edit_expense(user_id, id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to edit expense.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.execute("SELECT * FROM transactions WHERE id=%s AND user_id=%s AND transaction_type='expense'", (id, user_id))
        expense = cursor.fetchone()
        if not expense:
            flash('Expense not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('add_expense', user_id=user_id))
        cursor.execute("SELECT * FROM transactions WHERE user_id=%s AND transaction_type='expense' ORDER BY date DESC LIMIT 5", (user_id,))
        recent_expenses = cursor.fetchall()
        cursor.close()
        conn.close()
        today = datetime.now(nepal_tz).strftime('%Y-%m-%d')
        return render_template('add_expense.html', user=user, today=today, recent_expenses=recent_expenses, expense=expense, nepal_tz=nepal_tz)
    except Exception as e:
        logging.error(f"Edit expense error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('login'))

#DELETEEXPENSE
@app.route('/delete_expense/<int:user_id>/<int:id>', methods=['POST'])
def delete_expense(user_id, id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to delete expense.', 'danger')
        return redirect(url_for('login'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.execute("DELETE FROM transactions WHERE id=%s AND user_id=%s AND transaction_type='expense'", (id, user_id))
        conn.commit()
        flash('Expense deleted successfully!', 'success')
        cursor.close()
        conn.close()
        return redirect(url_for('add_expense', user_id=user_id))
    except Exception as e:
        logging.error(f"Delete expense error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('add_expense', user_id=user_id))

#VIEWREPORTS
@app.route('/visualize/<int:user_id>')
def visualize(user_id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to generate reports.', 'danger')
        return redirect(url_for('logout'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT full_name FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        cursor.execute('''
            SELECT date, category, amount, transaction_type 
            FROM transactions 
            WHERE user_id = %s
            ORDER BY date ASC
        ''', (user_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        if not data:
            flash('No transaction data available for visualization. Please add some transactions first.', 'warning')
            return redirect(url_for('dashboard', user_id=user_id))
        session['report_data'] = {'full_name': user['full_name']}
        flash('Reports generated successfully!', 'success')
        return redirect(url_for('download_reports', user_id=user_id))
    except Exception as e:
        logging.error(f"Visualize error: {str(e)}")
        flash(f'Error preparing reports: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('dashboard', user_id=user_id))

#DOWNLOADREPORTS
@app.route('/download_reports/<int:user_id>')
def download_reports(user_id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Please log in to access reports.', 'danger')
        return redirect(url_for('logout'))
    try:
        report_data = session.get('report_data', {})
        full_name = report_data.get('full_name')
        if not full_name:
            flash('Report data not found. Please generate reports again.', 'danger')
            return redirect(url_for('dashboard', user_id=user_id))
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('''
            SELECT date, category, amount, transaction_type 
            FROM transactions 
            WHERE user_id = %s
            ORDER BY date ASC
        ''', (user_id,))
        data = cursor.fetchall()
        cursor.close()
        conn.close()
        if not data:
            flash('No transaction data available for download. Please add transactions first.', 'danger')
            return redirect(url_for('dashboard', user_id=user_id))
        df = pd.DataFrame(
            [(row['date'], row['category'], row['amount'], row['transaction_type']) for row in data],
            columns=['DATE', 'CATEGORY', 'AMOUNT', 'TRANSACTION_TYPE']
        )
        df['DATE'] = pd.to_datetime(df['DATE'])
        df['AMOUNT'] = pd.to_numeric(df['AMOUNT'], errors='coerce')
        df = df.dropna(subset=['AMOUNT'])
        if df.empty:
            flash('No valid transaction data found after processing.', 'danger')
            return redirect(url_for('dashboard', user_id=user_id))
        excel_filename = f'{full_name}_transactions.xlsx'
        excel_buffer = io.BytesIO()
        with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Transactions', index=False)
            summary_data = []
            total_income = df[df['TRANSACTION_TYPE'] == 'income']['AMOUNT'].sum()
            total_expenses = df[df['TRANSACTION_TYPE'] == 'expense']['AMOUNT'].sum()
            summary_data.append(['Total Income', f'Rs {total_income:.2f}'])
            summary_data.append(['Total Expenses', f'Rs {total_expenses:.2f}'])
            net_balance = total_income - total_expenses
            if net_balance < 0:
                summary_data.append(['Net Balance', f'Deficit: Rs {abs(net_balance):.2f}'])
                summary_data.append(['Status', 'OVERSPENDING'])
                summary_data.append(['Recommended Action', 'Reduce expenses or increase income'])
            else:
                summary_data.append(['Net Balance', f'Rs {net_balance:.2f}'])
                summary_data.append(['Status', 'HEALTHY'])
            if total_income > 0:
                expense_ratio = (total_expenses / total_income) * 100
                summary_data.append(['Expense Ratio', f'{expense_ratio:.1f}%'])
                savings_rate = ((total_income - total_expenses) / total_income) * 100
                if savings_rate >= 0:
                    summary_data.append(['Savings Rate', f'{savings_rate:.1f}%'])
            summary_df = pd.DataFrame(summary_data, columns=['Category', 'Amount'])
            summary_df.to_excel(writer, sheet_name='Summary', index=False)
        chart_buffer = None
        expenses_df = df[df['TRANSACTION_TYPE'] == 'expense'].copy()
        if not expenses_df.empty:
            plt.style.use('default')
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            expense_summary = expenses_df.groupby('CATEGORY')['AMOUNT'].sum()
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8']
            ax1.pie(expense_summary.values, labels=expense_summary.index, autopct='%1.1f%%', 
                   colors=colors[:len(expense_summary)], startangle=90)
            ax1.set_title('Expense Distribution by Category', fontsize=14, fontweight='bold')
            expenses_df['month'] = expenses_df['DATE'].dt.to_period('M')
            monthly_expenses = expenses_df.groupby('month')['AMOUNT'].sum()
            bars = ax2.bar(range(len(monthly_expenses)), monthly_expenses.values, 
                          color='#FF6B6B', alpha=0.7)
            ax2.set_title('Monthly Expenses', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Month')
            ax2.set_ylabel('Amount (Rs)')
            ax2.set_xticks(range(len(monthly_expenses)))
            ax2.set_xticklabels([str(month) for month in monthly_expenses.index], rotation=45)
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'Rs {height:.0f}', ha='center', va='bottom', fontsize=9)
            df['month'] = df['DATE'].dt.to_period('M')
            monthly_data = df.groupby(['month', 'TRANSACTION_TYPE'])['AMOUNT'].sum().unstack(fill_value=0)
            if not monthly_data.empty:
                x_pos = range(len(monthly_data.index))
                width = 0.35
                if 'income' in monthly_data.columns:
                    ax3.bar([x - width/2 for x in x_pos], monthly_data['income'], 
                           width, label='Income', color='#4ECDC4', alpha=0.8)
                if 'expense' in monthly_data.columns:
                    ax3.bar([x + width/2 for x in x_pos], monthly_data['expense'], 
                           width, label='Expenses', color='#FF6B6B', alpha=0.8)
                ax3.set_title('Monthly Income vs Expenses', fontsize=14, fontweight='bold')
                ax3.set_xlabel('Month')
                ax3.set_ylabel('Amount (Rs)')
                ax3.set_xticks(x_pos)
                ax3.set_xticklabels([str(month) for month in monthly_data.index], rotation=45)
                ax3.legend()
                ax3.grid(axis='y', alpha=0.3)
            daily_expenses = expenses_df.groupby('DATE')['AMOUNT'].sum().reset_index()
            ax4.plot(daily_expenses['DATE'], daily_expenses['AMOUNT'], 
                    marker='o', linewidth=2, markersize=4, color='#FF6B6B')
            ax4.set_title('Daily Spending Pattern', fontsize=14, fontweight='bold')
            ax4.set_xlabel('Date')
            ax4.set_ylabel('Amount (Rs)')
            ax4.tick_params(axis='x', rotation=45)
            ax4.grid(alpha=0.3)
            plt.tight_layout()
            chart_buffer = io.BytesIO()
            plt.savefig(chart_buffer, format='png', dpi=300, bbox_inches='tight')
            plt.close()
            chart_buffer.seek(0)
        else:
            flash('No expense transactions available for chart generation. Excel report generated.', 'info')
        memory_file = io.BytesIO()
        with zipfile.ZipFile(memory_file, 'w', zipfile.ZIP_DEFLATED) as zf:
            excel_buffer.seek(0)
            zf.writestr(excel_filename, excel_buffer.read())
            if chart_buffer:
                chart_filename = f'{full_name}_financial_overview.png'
                chart_buffer.seek(0)
                zf.writestr(chart_filename, chart_buffer.read())
        memory_file.seek(0)
        session.pop('report_data', None)
        return send_file(
            memory_file,
            mimetype='application/zip',
            as_attachment=True,
            download_name=f'reports_{user_id}.zip'
        )
    except Exception as e:
        logging.error(f"Download reports error: {str(e)}")
        flash(f'Error downloading reports: {str(e)}', 'danger')
        return redirect(url_for('dashboard', user_id=user_id))

#VIEWREPORTS
@app.route('/view_reports/<int:user_id>')
def view_reports(user_id):
    if not is_logged_in():
        flash('Please log in to access the reports.', 'danger')
        return redirect(url_for('login'))
    if session['user_id'] != user_id:
        flash('You are not authorized to access these reports.', 'danger')
        return redirect(url_for('logout'))
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT * FROM users WHERE id=%s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('login'))
        current_month = datetime.now(nepal_tz).month
        current_year = datetime.now(nepal_tz).year
        cursor.execute('''SELECT transaction_type, category, amount, date, description
                       FROM transactions
                       WHERE user_id=%s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                       ORDER BY date DESC''', (user_id, current_month, current_year))
        transactions = cursor.fetchall()
        total_income = Decimal('0.0')
        total_expenses = Decimal('0.0')
        needs_spent = Decimal('0.0')
        wants_spent = Decimal('0.0')
        savings_made = Decimal('0.0')
        for transaction in transactions:
            amount = transaction['amount']
            transaction_type = transaction['transaction_type']
            category = transaction['category'].lower()
            if transaction_type == 'income' and category != 'savings':
                total_income += amount
            elif transaction_type == 'expense':
                total_expenses += amount
                if category == 'needs':
                    needs_spent += amount
                elif category == 'wants':
                    wants_spent += amount
                elif category == 'savings':
                    savings_made += amount
        net_balance = total_income - total_expenses - savings_made
        cursor.execute('SELECT * FROM budget_allocations WHERE user_id=%s', (user_id,))
        budget = cursor.fetchone()
        if not budget:
            needs_percent = Decimal('50.00')
            wants_percent = Decimal('30.00')
            savings_percent = Decimal('20.00')
        else:
            needs_percent = Decimal(str(budget['needs_percent'] or '50.00'))
            wants_percent = Decimal(str(budget['wants_percent'] or '30.00'))
            savings_percent = Decimal(str(budget['savings_percent'] or '20.00'))
        needs_budget = (needs_percent / 100) * total_income if total_income > 0 else Decimal('0.0')
        wants_budget = (wants_percent / 100) * total_income if total_income > 0 else Decimal('0.0')
        savings_budget = (savings_percent / 100) * total_income if total_income > 0 else Decimal('0.0')
        cursor.execute('''SELECT transaction_type, category, amount, date, description,
                                EXTRACT(MONTH FROM date) as month, EXTRACT(YEAR FROM date) as year
                       FROM transactions
                       WHERE user_id=%s
                       ORDER BY date DESC''', (user_id,))
        all_transactions = cursor.fetchall()
        formatted_transactions = []
        for transaction in all_transactions:
            formatted_transactions.append({
                'date': transaction['date'].astimezone(nepal_tz).strftime('%Y-%m-%d'),
                'type': transaction['transaction_type'],
                'category': transaction['category'],
                'amount': float(transaction['amount']),
                'description': transaction['description'],
                'month': transaction['month'],
                'year': transaction['year'],
                'is_current_month': (transaction['month'] == current_month and transaction['year'] == current_year)
            })
        cursor.close()
        conn.close()
        return render_template('view_reports.html', 
                             user=user,
                             username=user['full_name'],
                             total_income=float(total_income),
                             total_exp=float(total_expenses + savings_made),
                             net_balance=float(net_balance),
                             needs_spent=float(needs_spent),
                             wants_spent=float(wants_spent),
                             savings_saved=float(savings_made),
                             needs_budget=float(needs_budget),
                             wants_budget=float(wants_budget),
                             savings_budget=float(savings_budget),
                             transactions=formatted_transactions,
                             current_month=current_month,
                             current_year=current_year,
                             nepal_tz=nepal_tz)
    except Exception as e:
        logging.error(f"View reports error: {str(e)}")
        flash(f"Error loading reports: {str(e)}", 'danger')
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return redirect(url_for('login'))

#TOGGLEOTP
@app.route('/toggle_otp/<int:user_id>', methods=['POST'])
def toggle_otp(user_id):
    if not is_logged_in() or session['user_id'] != user_id:
        flash('Unauthorized access.', 'danger')
        return redirect(url_for('dashboard', user_id=user_id))
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(cursor_factory=DictCursor)
        cursor.execute('SELECT use_otp FROM users WHERE id = %s', (user_id,))
        user = cursor.fetchone()
        if not user:
            flash('User not found.', 'danger')
            cursor.close()
            conn.close()
            return redirect(url_for('dashboard', user_id=user_id))
        
        data = request.get_json()
        new_otp_status = data.get('use_otp', not user['use_otp'])
        cursor.execute('UPDATE users SET use_otp = %s WHERE id = %s', (new_otp_status, user_id))
        conn.commit()
        
        session.modified = True
        status_text = 'enabled' if new_otp_status else 'disabled'
        flash(f'2FA has been {status_text} successfully!', 'success')
        return redirect(url_for('dashboard', user_id=user_id))
    
    except Exception as e:
        logging.error(f"Toggle OTP error: {str(e)}")
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.rollback()
            conn.close()
        return redirect(url_for('dashboard', user_id=user_id))
    
    finally:
        if 'conn' in locals():
            cursor.close()
            conn.close()

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))