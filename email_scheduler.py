import time
from datetime import datetime
from flask import Flask, render_template, render_template_string
from flask_mail import Mail, Message
import psycopg2
from psycopg2.extras import DictCursor
from decimal import Decimal
import os
from dotenv import load_dotenv

load_dotenv()

# Create separate Flask app for scheduler
app = Flask(__name__)

# Configuration - using Aiven PostgreSQL
if os.environ.get('VERCEL'):
    DATABASE_URL = os.environ.get('DATABASE_URL', 'postgres://avnadmin:AVNS_oeoS7o2hf90qxX469cH@wealthwise-kaushalbikram44-25e1.b.aivencloud.com:18768/defaultdb?sslmode=require')
    app.config['MAIL_SERVER'] = 'smtp.gmail.com'
    app.config['MAIL_PORT'] = 587
    app.config['MAIL_USE_TLS'] = True
    app.config['MAIL_USERNAME'] = os.environ.get('EMAIL_USER', 'wisewealth32@gmail.com')
    app.config['MAIL_PASSWORD'] = os.environ.get('EMAIL_PASS', 'azxa ydvg oxfe rmer')
    app.config['MAIL_DEFAULT_SENDER'] = os.environ.get('EMAIL_USER', 'wisewealth32@gmail.com')
else:
    DATABASE_URL = 'postgresql://postgres:root@localhost/wealthwisenew'
    app.config['MAIL_SERVER'] = 'localhost'
    app.config['MAIL_PORT'] = 1025
    app.config['MAIL_USE_TLS'] = False
    app.config['MAIL_USERNAME'] = None
    app.config['MAIL_PASSWORD'] = None
    app.config['MAIL_DEFAULT_SENDER'] = 'noreply@wealthwise.com'

mail = Mail(app)

def get_db_connection():
    """Get database connection"""
    return psycopg2.connect(DATABASE_URL)

def send_daily_reminders():
    with app.app_context():
        try:
            conn = get_db_connection()
            cursor = conn.cursor(cursor_factory=DictCursor)
            cursor.execute('SELECT id, full_name, email FROM users')
            users = cursor.fetchall()
            
            if not users:
                print("No users found in database")
                cursor.close()
                conn.close()
                return
            
            for user in users:
                try:
                    user_id = user['id']
                    full_name = user['full_name']
                    email = user['email']
                    
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
                    
                    # Calculate budgets (50/30/20 rule)
                    needs_budget = Decimal('50.00') / 100 * total_income if total_income > 0 else Decimal('0.0')
                    wants_budget = Decimal('30.00') / 100 * total_income if total_income > 0 else Decimal('0.0')
                    savings_budget = Decimal('20.00') / 100 * total_income if total_income > 0 else Decimal('0.0')
                    
                    # Send email using template
                    msg = Message("Daily WealthWise Reminder", recipients=[email])
                    
                    # Try to use template file first, fall back to string template
                    try:
                        msg.html = render_template('daily_update.html',
                                                     full_name=full_name,
                                                     total_income=float(total_income),
                                                     needs_spent=float(needs_spent),
                                                     needs_budget=float(needs_budget),
                                                     wants_spent=float(wants_spent),
                                                     wants_budget=float(wants_budget),
                                                     savings_saved=float(savings_saved),
                                                     savings_budget=float(savings_budget))
                        
                    except Exception as template_error:
                        print(f"Template error for {email}: {template_error}")
                    
                    mail.send(msg)
                    print(f"Daily reminder sent to {email}")
                    
                except Exception as user_error:
                    print(f"Error processing user {user.get('email', 'unknown')}: {user_error}")
                    continue
                    
            cursor.close()
            conn.close()
            print(f"Daily reminders sent to {len(users)} users at {datetime.now()}")
            
        except Exception as e:
            print(f"Error sending daily reminders: {e}")
            import traceback
            traceback.print_exc()

def run_scheduler():
    last_sent_date = None
    print(f"WealthWise Email Scheduler started at {datetime.now()}")
    print("Waiting for scheduled time ")
    
    try:
        while True:
            current_time = datetime.now()
            current_date = current_time.date()
            
            # Send between (5-minute window)
            if (current_time.hour == 10 and 
                23 <= current_time.minute <= 25 and 
                last_sent_date != current_date):
                
                print(f"Triggering daily reminders at {current_time}")
                send_daily_reminders()
                last_sent_date = current_date
                print(f"Emails sent successfully at {current_time}")
                
            time.sleep(60)  # Check every minute
            
    except KeyboardInterrupt:
        print(f"\nScheduler stopped at {datetime.now()}")
        print("Goodbye!")
    except Exception as e:
        print(f"Scheduler error: {e}")
        import traceback
        traceback.print_exc()

if __name__ == '__main__':
    run_scheduler()