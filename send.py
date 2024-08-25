import smtplib
import ssl
import os
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import OpenSSL.SSL  # Added for improved error handling

# Load environment variables
load_dotenv()

# Setup email variables
sender_email = os.getenv('AUTH_USERNAME')
receiver_email = "william@predict.expert"
password = os.getenv('AUTH_PASSWORD')
smtp_server = os.getenv('HOSTNAME', '0.0.0.0')
port = int(os.getenv('SMTP_PORT', 465))

message = MIMEMultipart("alternative")
message["Subject"] = "Test email from SMTP server"
message["From"] = sender_email
message["To"] = receiver_email

text = "Hi William,\nThis is a test email sent from our new SMTP server.\nIf you're reading this, it means our server is working correctly!"
html = "<html><body><p>Hi William,<br>This is a test email sent from our new SMTP server.<br>If you're reading this, it means our server is working correctly!</p></body></html>"

part1 = MIMEText(text, "plain")
part2 = MIMEText(html, "html")

message.attach(part1)
message.attach(part2)

# Create an SSL context
context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE

print(f"Attempting to connect to {smtp_server} on port {port}")
print(f"Sender email: {sender_email}")
print(f"Recipient email: {receiver_email}")

try:
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server: 
        print(f"SSL connection established with {smtp_server}:{port}")
        server.set_debuglevel(1)
        server.login(sender_email, password)
        print("Login successful")
        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully")
except OpenSSL.SSL.Error as e:
    print(f"SSL error occurred: {str(e)}")
except Exception as e:
    print(f"Error: {e}")    