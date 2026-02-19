# config.py
# ------------------------------------
# This file holds all configurations
# like Secret Key, Database connection
# details, Email settings, Razorpay keys etc.
# ------------------------------------

SECRET_KEY = "abc123"   # used for sessions

# MySQL Database Configuration
DB_HOST = "localhost"
DB_USER = "root"
DB_PASSWORD = "root"  # keep empty if no password
DB_NAME = "smartcart_db1"


# Email SMTP Settings
MAIL_SERVER = 'smtp.gmail.com'
MAIL_PORT = 587
MAIL_USE_TLS = True
MAIL_USERNAME = 'shagabhavani003@gmail.com'
MAIL_PASSWORD = 'tmdo ukfd fhce gwav'   # Gmail App Password


RAZORPAY_KEY_ID = "rzp_test_SFxggQ95kEyTZc"
RAZORPAY_KEY_SECRET = "R2IKHXpMiYI7Jn3liu2sLlHa"
