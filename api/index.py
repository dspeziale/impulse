import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from flask import Flask, render_template, jsonify
from sqlalchemy import create_engine, text
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__, template_folder='../templates', static_folder='../static')
app.secret_key = os.getenv('SECRET_KEY', 'default-secret-key')

# Database Connection
DATABASE_URL = os.getenv('DATABASE_URL')
engine = None
if DATABASE_URL:
    try:
        engine = create_engine(DATABASE_URL)
    except Exception as e:
        print(f"Failed to connect to database: {e}")

# Email Configuration
GMAIL_USER = os.getenv('GMAIL_USER')
GMAIL_APP_PASSWORD = os.getenv('GMAIL_APP_PASSWORD')

def send_email(to_email, subject, body):
    if not GMAIL_USER or not GMAIL_APP_PASSWORD:
        print("Email credentials not set.")
        return False

    try:
        msg = MIMEMultipart()
        msg['From'] = GMAIL_USER
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP('smtp.gmail.com', 587)
        server.starttls()
        server.login(GMAIL_USER, GMAIL_APP_PASSWORD)
        text_msg = msg.as_string()
        server.sendmail(GMAIL_USER, to_email, text_msg)
        server.quit()
        return True
    except Exception as e:
        print(f"Failed to send email: {e}")
        return False

@app.route('/')
def index():
    db_status = "Disconnected"
    if engine:
        try:
            with engine.connect() as connection:
                connection.execute(text("SELECT 1"))
            db_status = "Connected"
        except Exception as e:
            db_status = f"Error: {str(e)}"
    
    return render_template('index.html', db_status=db_status)

@app.route('/test-email')
def test_email():
    # predefined email for testing
    if send_email(GMAIL_USER, "Test Email from Flask", "This is a test email."):
        return jsonify({"status": "success", "message": "Email sent successfully!"})
    else:
        return jsonify({"status": "error", "message": "Failed to send email."})

# Vercel requires the app to be available as a variable named 'app'
if __name__ == '__main__':
    app.run(debug=True)
