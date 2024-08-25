import smtplib
import ssl
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from dotenv import load_dotenv
import os

load_dotenv()

sender_email = os.getenv('AUTH_USERNAME')
receiver_email = "williambolduc404@gmail.com"
password = os.getenv('AUTH_PASSWORD')
smtp_server = os.getenv('HOSTNAME', '0.0.0.0')
port = int(os.getenv('SMTP_PORT', 465))

context = ssl.create_default_context()
context.check_hostname = False
context.verify_mode = ssl.CERT_NONE 

#server = smtplib.SMTP(smtp_server, port)  No need for this line
#server.starttls(context=context)  No need for this line

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

print(f"Attempting to connect to {smtp_server} on port {port}")
print(f"Sender email: {sender_email}")
print(f"Receiver email: {receiver_email}")

print("SSL Context Configuration:")
print(f"Minimum version: {context.minimum_version.name}")
print(f"Maximum version: {context.maximum_version.name}")
print("Cipher suites:")
for cipher in context.get_ciphers():
    print(f"  {cipher['name']}")

try:
    with smtplib.SMTP_SSL(smtp_server, port, context=context) as server: 
        print(f"SSL connection established with {smtp_server}:{port}")
        server.set_debuglevel(2)
        server.login(sender_email, password)
        print("Login successful")
        server.sendmail(sender_email, receiver_email, message.as_string())
        print("Email sent successfully")
except ssl.SSLError as e:
    print(f"SSL Error: {e}")
    print(f"SSL version: {ssl.OPENSSL_VERSION}")
except Exception as e:
    print(f"Error: {e}")

print(f"SSL version: {ssl.OPENSSL_VERSION}")