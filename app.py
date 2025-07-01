from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session
from flask_bcrypt import Bcrypt
from forms import RegistrationForm, LoginForm, ForgotPasswordForm, ResetPasswordForm
from flask_sqlalchemy import SQLAlchemy
import re
from flask_mail import Mail, Message
import pandas as pd
import matplotlib
matplotlib.use('Agg')  # Using non-interactive backend
import matplotlib.pylab as plt
import seaborn as sns
import os
from datetime import datetime, timedelta
from decimal import Decimal
import random 
import string
import psycopg2
from psycopg2.extras import DictCursor
from dotenv import load_dotenv
import pytz
from google import genai
load_dotenv()

app = Flask(__name__)

# Production configuration for PostgreSQL
if os.environ.get('RENDER'):
    # Using DATABASE_URL from Render (already formatted for PostgreSQL)
    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL').replace('postgres://', 'postgresql://')
    
    # Email config for production
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER')
    app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER')
else:
    # Local development with PostgreSQL
    app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://postgres:root@localhost/wealthwisenew'
    
    # Mailpit for local development
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 1025
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USERNAME'] = None
    app.config['MAIL_PASSWORD'] = None
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@wealthwise.com'

app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

app.secret_key = 'WealthWise'

# Critical email settings for production
app.config['TESTING'] = False
app.config['MAIL_DEBUG'] = True
app.config['MAIL_SUPPRESS_SEND'] = False
app.config['MAIL_FAIL_SILENTLY'] = False

# Initializing components
enc = Bcrypt(app)
mail = Mail(app)

app.config['WTF_CSRF_ENABLED'] = True

# Nepal Time zone
nepal_tz = pytz.timezone('Asia/Kathmandu')

# PostgreSQL configuration for raw queries
def get_db_connection():
    if os.environ.get('RENDER'):
        conn = psycopg2.connect(os.environ.get('DATABASE_URL'))
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

@app.route('/')
def home():
    return redirect(url_for('login'))

#LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    log = LoginForm()
    if log.validate_on_submit():
        input_data = log.email_or_phone.data.strip()
        pw = log.password.data

        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)

            # Check if a password reset is pending
            if 'reset_token' in session:
                flash('Please reset your password using the link sent to your email before logging in.', 'danger')
                return redirect(url_for('forgot_password'))

            # Check if another user is already logged in
            if 'user_id' in session:
                flash('Another user is already logged in. Please log out before logging in with a different account.', 'danger')
                return redirect(url_for('logout'))

            if is_email(input_data):
                cursor.execute('SELECT * FROM users WHERE email = %s', (input_data,))
            else:
                phone = re.sub(r'^\+977', '', input_data).strip()
                cursor.execute('SELECT * FROM users WHERE phone_number = %s', (phone,))
                
            account = cursor.fetchone()

            if account:
                stored_hashed_pw = account['password_hash']
                full_name = account['full_name']
                email = account['email']
                if enc.check_password_hash(stored_hashed_pw, pw):
                    # Check if OTP data already exists to avoid resending
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
                        try:
                            msg = Message("Your Wealthwise OTP", recipients=[email])
                            msg.html = render_template("otp_email.html", full_name=full_name, otp=otp)
                            mail.send(msg)
                            flash("An OTP has been sent to your mail", 'info')
                        except Exception as email_error:
                            flash(f'Error Sending OTP: {str(email_error)}', 'danger')
                    return redirect(url_for('verify_otp'))
                else:
                    flash('Invalid Password', 'danger')
            else:
                flash('User not registered or invalid credentials', 'danger')

            cursor.close()
            conn.close()

        except Exception as e:
            flash(f"Error occurred: {e}", "danger")
            if 'conn' in locals():
                conn.rollback()
                conn.close()
            
    return render_template('login.html', form=log)

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

    # Regenerate and resend OTP
    otp = generate_otp()
    otp_expiry = (datetime.now(nepal_tz) + timedelta(minutes=5)).timestamp()
    otp_data.update({
        'otp': otp,
        'expires': otp_expiry,
        'attempts': 0,  # Reset attempts on resend
        'lockout_time': None  # Clear lockout on resend
    })
    session['otp_data'] = otp_data

    try:
        email = otp_data['email']
        full_name = otp_data['full_name']
        msg = Message("Your Wealthwise OTP", recipients=[email])
        msg.html = render_template("otp_email.html", full_name=full_name, otp=otp)
        mail.send(msg)
        flash('A new OTP has been sent to your email.', 'success')
    except Exception as email_error:
        flash(f'Error sending OTP: {str(email_error)}', 'danger')
        return redirect(url_for('verify_otp'))

    return redirect(url_for('verify_otp'))

#VERIFYOTP
@app.route('/verify_otp', methods=['GET', 'POST'])
def verify_otp():
    otp_data = session.get('otp_data')
    if not otp_data:
        flash('No OTP session found. Please login again', 'danger')
        return redirect(url_for('login'))
    
    if datetime.now(nepal_tz).timestamp() > otp_data['expires']:
        session.pop('otp_data', None)
        flash('OTP has expired. Please Login again to receive a new OTP', 'danger')
        return redirect(url_for('login'))
    
    # Checking for invalid attempts
    if otp_data.get('lockout_time') and datetime.now(nepal_tz).timestamp() < otp_data['lockout_time']:
        remaining_time = int(otp_data['lockout_time'] - datetime.now(nepal_tz).timestamp())
        flash(f'Too many invalid attempts. Please wait {remaining_time} seconds for a new OTP.', 'danger')
        return render_template('verify_otp.html')
    
    if request.method == 'POST':
        user_otp = request.form.get('otp', '').strip()
        otp_data['attempts'] += 1
        session['otp_data'] = otp_data  # Updating session with new attempt count
    
        if user_otp == otp_data['otp']:
            session['user_id'] = otp_data['user_id']
            email = otp_data['email']
            full_name = otp_data['full_name']
            session.pop('otp_data', None)
            
            flash('Login Successful', 'success')
            return redirect(url_for('dashboard', user_id=otp_data['user_id']))
        
        else:
            if otp_data['attempts'] >= 5:
                otp_data['lockout_time'] = (datetime.now(nepal_tz) + timedelta(minutes=5)).timestamp()
                session['otp_data'] = otp_data
                flash('Too many invalid OTP attempts. A new OTP will be sent after 5 minutes.', 'danger')
                return render_template('verify_otp.html')
            else:
                flash('Invalid OTP. Please try again. Attempts remaining: {}'.format(5 - otp_data['attempts']), 'danger')
    
    return render_template('verify_otp.html')

#FORGOTPASSWORD
@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    form = ForgotPasswordForm()
    if form.validate_on_submit():
        identifier = form.identifier.data.strip()  # Can be email or phone
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
                # Generating a simple token (user ID + timestamp)
                token = f"{user['id']}-{int(datetime.now(nepal_tz).timestamp())}"
                reset_url = url_for('reset_password', token=token, _external=True)
                session['reset_token'] = {
                    'token': token,
                    'email': user['email'],
                    'phone': user['phone_number'],
                    'expires': (datetime.now(nepal_tz) + timedelta(minutes=2)).timestamp()
                }

                # Sending reset email
                try:
                    msg = Message("Password Reset Request", recipients=[user['email']])
                    msg.html = render_template("password_reset_email.html", full_name=user['full_name'], reset_url=reset_url)
                    mail.send(msg)
                    flash('A password reset link has been sent to your email.', 'success')
                except Exception as email_error:
                    flash(f'Error sending email: {str(email_error)}', 'danger')
                    raise  # Re-raise for full stack trace
            else:
                flash('Identifier not found. Please register first.', 'danger')
                return redirect(url_for('registration'))

            cursor.close()
            conn.close()

        except Exception as e:
            flash(f'Error occurred: {str(e)}', 'danger')
            if 'conn' in locals():
                conn.rollback()
                conn.close()

        return redirect(url_for('login'))

    return render_template('forgot_password.html', form=form)

#RESETPASSWORD
@app.route('/reset_password/<token>', methods=['GET', 'POST'])
def reset_password(token):
    # Validate token
    reset_data = session.get('reset_token')
    if not reset_data or reset_data['token'] != token or datetime.now(nepal_tz).timestamp() > reset_data['expires']:
        flash('Invalid or expired reset link.', 'danger')
        return redirect(url_for('forgot_password'))

    if is_logged_in():
        session.pop('user_id', None)
        flash('You have been logged out to reset your password.', 'info')
        
    form = ResetPasswordForm()
    # Fetch the current password hash for the user
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

                # Clear the reset token
                session.pop('reset_token', None)
                flash('Your password has been reset successfully. Please log in.', 'success')
                return redirect(url_for('login'))

            except Exception as e:
                flash(f'Error occurred: {str(e)}', 'danger')
                conn.rollback()

            finally:
                cursor.close()
                conn.close()

        cursor.close()
        conn.close()

    except Exception as e:
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
    
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            phone_num = re.sub(r'^\+977', '', phone_num).strip()
            cursor.execute('SELECT * FROM users WHERE phone_number=%s OR email=%s', (phone_num, email))
            account = cursor.fetchone()
            if account:
                if account['phone_number'] == phone_num:
                    flash('Phone Number Already Registered! Please use a new number', 'danger')
                elif account['email'] == email:
                    flash('Email Already Registered! Please use a new email', 'danger')
                cursor.close()
                conn.close()
                return redirect(url_for('registration'))
            else:
                hash_pw = enc.generate_password_hash(pw).decode('utf-8')
                cursor.execute('''
                    INSERT INTO users (full_name, email, phone_number, address, password_hash)
                    VALUES (%s, %s, %s, %s, %s)
                ''', (full_name, email, phone_num, address, hash_pw))

                conn.commit()
                try:
                    msg = Message("Welcome to WealthWise!", recipients=[email])
                    msg.html = render_template("welcome_mail.html", full_name=full_name)
                    mail.send(msg)
                except Exception as email_error:
                    print(f'Error sending welcome email: {str(email_error)}')
                    flash('Registration successful, but failed to send welcome email.', 'warning')

                cursor.close()
                conn.close()
                flash('You Have Successfully Registered!', 'success')
                return redirect(url_for('login'))

        except Exception as e:
            flash(f'Error occurred: {e}', 'danger')
            if 'conn' in locals():
                conn.rollback()
                conn.close()

    return render_template('register.html', form=form)

#LOGOUT
@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

#DASHBOARD
@app.route('/dashboard/<int:user_id>')
def dashboard(user_id):
    if not is_logged_in() or session['user_id'] != user_id:
        return redirect(url_for('login'))
    
    conn = get_db_connection()
    cursor = conn.cursor(cursor_factory=DictCursor)
    
    # Get current month/year in Nepal Time
    current_month = datetime.now(nepal_tz).month
    current_year = datetime.now(nepal_tz).year
    
    # Get user's budget allocation preferences
    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
    allocation = cursor.fetchone()
    
    if not allocation:
        # Create default 50/30/20 allocation
        cursor.execute('''
            INSERT INTO budget_allocations (user_id, needs_percent, wants_percent, savings_percent, total_budget)
            VALUES (%s, 50.00, 30.00, 20.00, 0.00)
        ''', (user_id,))
        conn.commit()
        allocation = {'needs_percent': 50, 'wants_percent': 30, 'savings_percent': 20, 'total_budget': 0}
    
    # Calculate monthly data dynamically from transactions
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN transaction_type = 'income' AND category != 'savings' THEN amount ELSE 0 END) as monthly_income,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'needs' THEN amount ELSE 0 END) as needs_spent,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'wants' THEN amount ELSE 0 END) as wants_spent,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'savings' THEN amount ELSE 0 END) as savings_made
        FROM transactions 
        WHERE user_id = %s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
    ''', (user_id, current_month, current_year))
    
    monthly_data = cursor.fetchone()
    
    # Calculate monthly budget limits based on actual income (not including savings)
    monthly_income = monthly_data['monthly_income'] or 0
    needs_limit = (monthly_income * allocation['needs_percent']) / 100
    wants_limit = (monthly_income * allocation['wants_percent']) / 100
    savings_target = (monthly_income * allocation['savings_percent']) / 100
    
    # Calculate remaining budgets
    needs_remaining = needs_limit - (monthly_data['needs_spent'] or 0)
    wants_remaining = wants_limit - (monthly_data['wants_spent'] or 0)
    savings_remaining = savings_target - (monthly_data['savings_made'] or 0)
    
    # Get user info
    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    
    cursor.close()
    conn.close()
    
    # Add current month name
    current_month_name = datetime.now(nepal_tz).strftime('%B')
    
    return render_template('dashboard.html', 
                         user=user,
                         monthly_income=monthly_income,
                         needs_limit=needs_limit,
                         wants_limit=wants_limit,
                         savings_target=savings_target,
                         needs_spent=monthly_data['needs_spent'] or 0,
                         wants_spent=monthly_data['wants_spent'] or 0,
                         savings_made=monthly_data['savings_made'] or 0,
                         needs_remaining=max(0, needs_remaining),
                         wants_remaining=max(0, wants_remaining),
                         savings_remaining=max(0, savings_remaining),
                         current_month_name=current_month_name,
                         current_year=current_year,
                         monthly_expenses=(monthly_data['needs_spent'] or 0) + (monthly_data['wants_spent'] or 0),
                         nepal_tz=nepal_tz)

#CHATBOT
@app.route('/chatbot/<int:user_id>', methods=['GET', 'POST'])
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
        
        # Get user's financial data
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
        
        # Financial data summary
        financial_data = (
            f"Total Income: Rs {float(total_income):.2f}, "
            f"Needs Spent: Rs {float(needs_spent):.2f} (Budget: 50%), "
            f"Wants Spent: Rs {float(wants_spent):.2f} (Budget: 30%), "
            f"Savings: Rs {float(savings_saved):.2f} (Goal: 20%)"
        )
        
        cursor.close()
        conn.close()
        
        if request.method == 'POST':
            user_message = request.form.get('message', '').strip()
            context = request.form.get('context', '').strip()
            
            if not user_message:
                return jsonify({'response': 'Please enter a message.'}), 400
            
            try:
                # NEW GEMINI API CONFIGURATION
                if os.environ.get('RENDER'):
                    api_key = os.environ.get('GEMINI_API_KEY')
                else:
                    api_key = 'AIzaSyBaze8MZi4ZxPWWV0w1dFs50_07lyWtcOs'
                
                # Initialize the new Gemini client
                client = genai.Client(api_key=api_key)
                
                # Create prompt for financial advisor
                prompt = f"""
                You are a financial advisor for WealthWise, a finance management app for students in Nepal. 
                Provide concise, accurate financial advice (under 100 words) in NPR, focusing on budgeting and differentiating needs vs. wants.
                
                Needs are essential expenses (rent, groceries, utilities); wants are non-essential (entertainment, dining out).
                Average income of Nepalese students: Rs 5,000-25,000.
                
                User's financial data: {financial_data}
                
                Previous conversation: {context}
                
                User question: {user_message}
                
                Provide helpful financial advice. Please answer in two sentences or less.
                """
                
                # Generate response using NEW API
                response = client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt
                )
                
                ai_response = response.text
                
                # Update context
                new_context = f"{context}\nUser: {user_message}\nAI: {ai_response}".strip()
                
                return jsonify({'response': ai_response, 'context': new_context})
                
            except Exception as ai_error:
                print(f"Gemini API error: {str(ai_error)}")
                return jsonify({'response': 'Sorry, the AI assistant is temporarily unavailable. Please try again later.'}), 500
        
        # Handle GET request
        prefilled_question = request.args.get('question', '')
        return render_template('chatbot.html', user=user, full_name=full_name, prefilled_question=prefilled_question)
    
    except Exception as e:
        if 'conn' in locals():
            conn.close()
        return jsonify({'response': f'Error: {str(e)}'}), 500

#ADDINCOME
@app.route('/add_income/<int:user_id>', methods=['GET','POST'])
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
                # Convert date string to datetime with current time
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                current_time = datetime.now(nepal_tz).time()
                full_datetime = datetime.combine(date_obj.date(), current_time)
                
                if income_id:
                    # Update existing income
                    cursor.execute(
                        "UPDATE transactions SET amount=%s, category=%s, date=%s, description=%s WHERE id=%s AND user_id=%s",
                        (Decimal(amount), category, full_datetime, description, income_id, user_id)
                    )
                    flash('Income updated successfully!', 'success')
                else:
                    # Add new income
                    cursor.execute(
                        "INSERT INTO transactions (user_id, transaction_type, category, amount, date, description) VALUES (%s, 'income', %s, %s, %s, %s)",
                        (user_id, category, Decimal(amount), full_datetime, description)
                    )
                    flash('Income added successfully!', 'success')
                
                conn.commit()
                return redirect(url_for('add_income', user_id=user_id))
                
            except Exception as e:
                flash(f'Error adding income: {str(e)}', 'danger')
                print(f"Error in add_income: {str(e)}")

    # Get recent income transactions for CURRENT MONTH
    current_month = datetime.now(nepal_tz).month
    current_year = datetime.now(nepal_tz).year
    cursor.execute('''
        SELECT * FROM transactions 
        WHERE user_id=%s AND transaction_type='income' 
        AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s 
        ORDER BY date DESC LIMIT 5
    ''', (user_id, current_month, current_year))
    recent_incomes = cursor.fetchall()

    # Get user info
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
        
        # Delete the income record
        cursor.execute("DELETE FROM transactions WHERE id=%s AND user_id=%s AND transaction_type='income'", (income_id, user_id))
        conn.commit()
        
        flash('Income deleted successfully!', 'success')
        cursor.close()
        conn.close()
        return redirect(url_for('add_income', user_id=user_id))
    
    except Exception as e:
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
                # Converting date string to datetime with current time
                date_obj = datetime.strptime(date_str, '%Y-%m-%d')
                current_time = datetime.now(nepal_tz).time()
                full_datetime = datetime.combine(date_obj.date(), current_time)
                
                if expense_id:
                    # Updating existing expense or savings
                    cursor.execute(
                        "UPDATE transactions SET amount=%s, category=%s, date=%s, description=%s WHERE id=%s AND user_id=%s",
                        (Decimal(amount), category, full_datetime, description, expense_id, user_id)
                    )
                    if category.lower() == 'savings':
                        flash('Savings updated successfully!', 'success')
                    else:
                        flash('Expense updated successfully!', 'success')
                else:
                    # Adding new expense or savings
                    cursor.execute(
                        "INSERT INTO transactions (user_id, transaction_type, category, amount, date, description) VALUES (%s, 'expense', %s, %s, %s, %s)",
                        (user_id, category, Decimal(amount), full_datetime, description)
                    )
                    if category.lower() == 'savings':
                        flash('Savings added successfully!', 'success')
                    else:
                        flash('Expense added successfully!', 'success')
                
                conn.commit()
                
                # Only check budget warnings for 'needs' and 'wants', not 'savings'
                if category.lower() in ['needs', 'wants']:
                    current_month = datetime.now(nepal_tz).month
                    current_year = datetime.now(nepal_tz).year
                    
                    # Getting user info for email
                    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
                    user = cursor.fetchone()
                    
                    # Get monthly income (excluding savings from income)
                    cursor.execute('''
                        SELECT SUM(amount) as monthly_income 
                        FROM transactions 
                        WHERE user_id = %s AND transaction_type = 'income' AND category != 'savings'
                        AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                    ''', (user_id, current_month, current_year))
                    
                    income_result = cursor.fetchone()
                    monthly_income = income_result['monthly_income'] or 0
                    
                    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
                    allocation = cursor.fetchone()
                    
                    if allocation and monthly_income > 0:
                        # Calculating limits for needs and wants only
                        if category.lower() == 'needs':
                            limit = (monthly_income * allocation['needs_percent']) / 100
                            category_name = "Needs"
                        elif category.lower() == 'wants':
                            limit = (monthly_income * allocation['wants_percent']) / 100
                            category_name = "Wants"
                        
                        # Check current spending AFTER adding this expense
                        cursor.execute('''
                            SELECT SUM(amount) as spent 
                            FROM transactions 
                            WHERE user_id = %s AND transaction_type = 'expense' 
                            AND category = %s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                        ''', (user_id, category, current_month, current_year))
                        
                        spent_result = cursor.fetchone()
                        current_spent = spent_result['spent'] or 0
                        percentage_used = (current_spent / limit) * 100 if limit > 0 else 0
                        
                        # Sending email warnings based on budget status
                        if current_spent > limit:
                            # Over budget - send warning email
                            overage = current_spent - limit
                            flash(f'Budget Alert: You have exceeded your {category_name} budget by Rs {overage:.2f} this month. Warning Email has been sent', 'warning')
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
                            except Exception as email_error:
                                print(f'Error sending budget warning email: {str(email_error)}')
                        elif percentage_used >= 80:  # 80% threshold
                            remaining = limit - current_spent
                            flash(f'Budget Notice: You have Rs {remaining:.2f} remaining in your {category_name} budget this month. Warning Email has been sent', 'info')
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
                            except Exception as email_error:
                                print(f'Error sending budget alert email: {str(email_error)}')
                
                # Tracking savings progress (no warnings, just info)
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
                    monthly_income = income_result['monthly_income'] or 0
                    
                    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
                    allocation = cursor.fetchone()
                    
                    if allocation and monthly_income > 0:
                        savings_target = (monthly_income * allocation['savings_percent']) / 100
                        cursor.execute('''
                            SELECT SUM(amount) as saved 
                            FROM transactions 
                            WHERE user_id = %s AND transaction_type = 'expense' 
                            AND category = 'savings' AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
                        ''', (user_id, current_month, current_year))
                        saved_result = cursor.fetchone()
                        current_saved = saved_result['saved'] or 0
                        
                        if current_saved >= savings_target:
                            flash(f'Great job! You have saved Rs {current_saved:.2f}, meeting your savings target of Rs {savings_target:.2f} this month.', 'success')
                        else:
                            remaining = savings_target - current_saved
                            flash(f'Savings Update: You have saved Rs {current_saved:.2f}. Aim to save Rs {remaining:.2f} more to meet your target of Rs {savings_target:.2f}.', 'info')
                
                return redirect(url_for('add_expense', user_id=user_id))
                
            except Exception as e:
                flash(f'Error adding expense: {str(e)}', 'danger')
                print(f"Error in add_expense: {str(e)}")

    # Getting recent expense transactions for CURRENT MONTH
    current_month = datetime.now(nepal_tz).month
    current_year = datetime.now(nepal_tz).year
    
    cursor.execute('''
        SELECT * FROM transactions 
        WHERE user_id=%s AND transaction_type='expense' 
        AND EXTRACT(MONTH FROM date)=%s AND EXTRACT(YEAR FROM date)=%s 
        ORDER BY date DESC LIMIT 5
    ''', (user_id, current_month, current_year))
    recent_expenses = cursor.fetchall()

    # Getting user info
    cursor.execute("SELECT * FROM users WHERE id=%s", (user_id,))
    user = cursor.fetchone()
    
    # Getting monthly budget data (excluding savings from income)
    cursor.execute('''
        SELECT 
            SUM(CASE WHEN transaction_type = 'income' AND category != 'savings' THEN amount ELSE 0 END) as monthly_income,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'needs' THEN amount ELSE 0 END) as needs_spent,
            SUM(CASE WHEN transaction_type = 'expense' AND category = 'wants' THEN amount ELSE 0 END) as wants_spent
        FROM transactions 
        WHERE user_id = %s AND EXTRACT(MONTH FROM date) = %s AND EXTRACT(YEAR FROM date) = %s
    ''', (user_id, current_month, current_year))

    monthly_data = cursor.fetchone()
    monthly_income = monthly_data['monthly_income'] or 0

    # Getting budget allocation
    cursor.execute("SELECT * FROM budget_allocations WHERE user_id = %s", (user_id,))
    allocation = cursor.fetchone()

    if allocation and monthly_income > 0:
        needs_limit = (monthly_income * allocation['needs_percent']) / 100
        wants_limit = (monthly_income * allocation['wants_percent']) / 100
    else:
        needs_limit = 0
        wants_limit = 0
    
    cursor.close()
    conn.close()
    return render_template('add_expense.html', 
                         user=user, 
                         recent_expenses=recent_expenses,
                         needs_spent=monthly_data['needs_spent'] or 0,
                         wants_spent=monthly_data['wants_spent'] or 0,
                         needs_limit=needs_limit,
                         wants_limit=wants_limit,
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
        flash(f'Error: {str(e)}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('add_expense', user_id=user_id))

#VISUALIZE
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
            
        full_name = user['full_name']
           
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

        # Explicitly specify column names when creating DataFrame
        df = pd.DataFrame(
            [(row['date'], row['category'], row['amount'], row['transaction_type']) for row in data],
            columns=['DATE', 'CATEGORY', 'AMOUNT', 'TRANSACTION_TYPE']
        )
        
        # Ensure proper data types
        df['DATE'] = pd.to_datetime(df['DATE'])
        df['AMOUNT'] = pd.to_numeric(df['AMOUNT'], errors='coerce')
        
        # Remove any rows with NaN amounts
        df = df.dropna(subset=['AMOUNT'])
        
        if df.empty:
            flash('No valid transaction data found after processing.', 'warning')
            return redirect(url_for('dashboard', user_id=user_id))

        # Create directories
        reports_dir = os.path.join('Offlinereports', 'reports')
        charts_dir = os.path.join('Offlinereports', 'charts')
        os.makedirs(reports_dir, exist_ok=True)
        os.makedirs(charts_dir, exist_ok=True)

        # Save to Excel with proper formatting
        excel_filename = f'{full_name}_transactions.xlsx'
        excel_path = os.path.join(reports_dir, excel_filename)
        
        with pd.ExcelWriter(excel_path, engine='openpyxl') as writer:
            df.to_excel(writer, sheet_name='Transactions', index=False)
            
            # Adding summary sheet
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

        print(f"Excel file saved to: {excel_path}")

        # Generate charts with error handling
        plt.style.use('default')
        
        # Chart 1: Expense distribution
        expenses_df = df[df['TRANSACTION_TYPE'] == 'expense'].copy()
        
        if not expenses_df.empty:
            fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 12))
            
            # Pie chart for expenses
            expense_summary = expenses_df.groupby('CATEGORY')['AMOUNT'].sum()
            colors = ['#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7', '#DDA0DD', '#98D8C8']
            
            ax1.pie(expense_summary.values, labels=expense_summary.index, autopct='%1.1f%%', 
                   colors=colors[:len(expense_summary)], startangle=90)
            ax1.set_title('Expense Distribution by Category', fontsize=14, fontweight='bold')
            
            # Monthly expenses bar chart
            expenses_df['month'] = expenses_df['DATE'].dt.to_period('M')
            monthly_expenses = expenses_df.groupby('month')['AMOUNT'].sum()
            
            bars = ax2.bar(range(len(monthly_expenses)), monthly_expenses.values, 
                          color='#FF6B6B', alpha=0.7)
            ax2.set_title('Monthly Expenses', fontsize=14, fontweight='bold')
            ax2.set_xlabel('Month')
            ax2.set_ylabel('Amount (Rs)')
            ax2.set_xticks(range(len(monthly_expenses)))
            ax2.set_xticklabels([str(month) for month in monthly_expenses.index], rotation=45)
            
            # Add value labels on bars
            for bar in bars:
                height = bar.get_height()
                ax2.text(bar.get_x() + bar.get_width()/2., height + height*0.01,
                        f'Rs {height:.0f}', ha='center', va='bottom', fontsize=9)
        
            # Income vs Expenses comparison
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
            
            # Daily spending pattern
            daily_expenses = expenses_df.groupby('DATE')['AMOUNT'].sum().reset_index()
            ax4.plot(daily_expenses['DATE'], daily_expenses['AMOUNT'], 
                    marker='o', linewidth=2, markersize=4, color='#FF6B6B')
            ax4.set_title('Daily Spending Pattern', fontsize=14, fontweight='bold')
            ax4.set_xlabel('Date')
            ax4.set_ylabel('Amount (Rs)')
            ax4.tick_params(axis='x', rotation=45)
            ax4.grid(alpha=0.3)

            plt.tight_layout()
            
            chart_filename = f'{full_name}_financial_overview.png'
            chart_path = os.path.join(charts_dir, chart_filename)
            plt.savefig(chart_path, dpi=300, bbox_inches='tight')
            plt.close()

        # Store chart filenames in session
        session['chart_files'] = {
            'overview': chart_filename,
            'patterns': chart_filename,
            'excel': excel_filename
        }

        flash('Reports generated successfully!', 'success')
        return redirect(url_for('dashboard', user_id=user_id))
    
    except Exception as e:
        print(f"Error in visualize function: {str(e)}")
        flash(f'Error generating visualizations: {e}', 'danger')
        if 'conn' in locals():
            conn.close()
        return redirect(url_for('dashboard', user_id=user_id))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()  # Create tables if they don't exist
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))