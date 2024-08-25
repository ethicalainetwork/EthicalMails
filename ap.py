import os
import ssl
import asyncio
import logging
import socket
from aiosmtpd.controller import Controller
from aiosmtpd.smtp import SMTP as SMTPServer
from email import message_from_bytes
from dotenv import load_dotenv
import dns.resolver
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

# Load environment variables
load_dotenv()

# Configure DNS resolver to use Google's public DNS servers
dns.resolver.default_resolver = dns.resolver.Resolver(configure=False)
dns.resolver.default_resolver.nameservers = ['8.8.8.8', '8.8.4.4']

class CustomSMTPHandler:
    def __init__(self):
        self.max_message_size = int(os.getenv('MAX_MESSAGE_SIZE', 10485760))
        self.relay_domains = os.getenv('RELAY_DOMAINS', '').split(',')
        self.max_recipients = int(os.getenv('MAX_RECIPIENTS', 50))
        self.blacklisted_ips = os.getenv('BLACKLISTED_IPS', '').split(',')

    async def handle_RCPT(self, server, session, envelope, address, rcpt_options):
        if len(envelope.rcpt_tos) >= self.max_recipients:
            return f'552 Too many recipients, maximum is {self.max_recipients}'
        
        domain = address.split('@')[-1]
        if domain not in self.relay_domains:
            return f'550 Relay not permitted for {domain}'
        
        envelope.rcpt_tos.append(address)
        return '250 OK'

    async def handle_DATA(self, server, session, envelope):
        if session.peer[0] in self.blacklisted_ips:
            return '550 IP blacklisted'

        if len(envelope.content) > self.max_message_size:
            return f'552 Message size exceeds maximum of {self.max_message_size} bytes'

        # Process the message
        message = message_from_bytes(envelope.content)
        
        # Here you would typically save the email or forward it
        # For now, we'll just log it
        logging.info(f"Received message from {envelope.mail_from} for {envelope.rcpt_tos}")
        logging.info(f"Subject: {message['subject']}")

        return '250 Message accepted for delivery'

async def get_mx_record(domain):
    try:
        mx_records = await asyncio.to_thread(dns.resolver.resolve, domain, 'MX')
        return str(mx_records[0].exchange)
    except Exception as e:
        logging.error(f"Failed to get MX record for {domain}: {e}")
        return None

def generate_self_signed_cert(cert_file, key_file):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate a self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, os.getenv('DOMAIN')),
    ])
    cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=365)
    ).add_extension(
        x509.SubjectAlternativeName([x509.DNSName(os.getenv('DOMAIN'))]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Write our key and certificate out
    with open(key_file, "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(cert_file, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    logging.info(f"Generated self-signed certificate for {os.getenv('DOMAIN')}")

def create_ssl_context():
    cert_file = os.getenv('TLS_CERT_FILE')
    key_file = os.getenv('TLS_KEY_FILE')

    if not os.path.exists(cert_file) or not os.path.exists(key_file):
        logging.info("Certificate or key file not found. Generating self-signed certificate...")
        generate_self_signed_cert(cert_file, key_file)

    ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    ssl_context.load_cert_chain(
        certfile=cert_file,
        keyfile=key_file
    )
    return ssl_context

class CustomController(Controller):
    def __init__(self, handler, loop=None, hostname=None, port=None, *args, **kwargs):
        self.custom_loop = loop or asyncio.get_event_loop()
        super().__init__(handler, hostname=hostname, port=port, *args, **kwargs)

    async def start(self):
        try:
            self.server = await self.custom_loop.create_server(
                lambda: self.factory(),
                host=self.hostname,
                port=self.port,
                ssl=self.ssl_context,
            )
            self.custom_loop.create_task(self._run())
        except Exception as e:
            logging.error(f"Failed to start server: {e}")
            raise

    async def _run(self):
        async with self.server:
            await self.server.serve_forever()

def is_hostname_resolvable(hostname):
    try:
        socket.gethostbyname(hostname)
        return True
    except socket.error:
        return False
async def amain():
    hostname = os.getenv('HOSTNAME')
    domain = os.getenv('DOMAIN')
    port = int(os.getenv('PORT', 25))

    if not is_hostname_resolvable(hostname):
        logging.error(f"Hostname {hostname} is not resolvable. Please check your DNS configuration.")
        return

    mx_record = await get_mx_record(domain)
    if mx_record:
        # Remove trailing dot from MX record if present
        mx_record = mx_record.rstrip('.')
        if mx_record.lower() == hostname.lower():
            logging.info(f"MX record for {domain} matches this server's hostname.")
        else:
            logging.warning(f"MX record for {domain} ({mx_record}) does not match this server's hostname ({hostname}).")
    else:
        logging.warning(f"Could not retrieve MX record for {domain}. The server will continue to start, but email delivery might be affected.")

    use_tls = os.getenv('USE_TLS', 'false').lower() == 'true'
    require_auth = os.getenv('REQUIRE_AUTH', 'false').lower() == 'true'

    ssl_context = create_ssl_context() if use_tls else None

    controller = CustomController(
        CustomSMTPHandler(),
        hostname=hostname,
        port=port,
        ssl_context=ssl_context,
        server_class=SMTPServer,
        require_starttls=use_tls,
        auth_required=require_auth,
        auth_callback=lambda username, password: (username == os.getenv('AUTH_USERNAME') and password == os.getenv('AUTH_PASSWORD')),
        max_client_count=int(os.getenv('MAX_CONNECTIONS', 100))
    )

    try:
        await controller.start()
        logging.info(f"SMTP server running on {hostname}:{port}")
        logging.info(f"TLS: {'Enabled' if use_tls else 'Disabled'}")
        logging.info(f"Authentication: {'Required' if require_auth else 'Not required'}")
    except Exception as e:
        logging.error(f"Failed to start SMTP server: {e}")
        return

    while True:
        await asyncio.sleep(3600)  # Run indefinitely

def setup_logging():
    log_file = os.getenv('LOG_FILE', './smtp_server.log')
    log_level = getattr(logging, os.getenv('LOG_LEVEL', 'INFO'))

    logging.basicConfig(
        level=log_level,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.StreamHandler(),  # Log to console
            logging.FileHandler(log_file)  # Log to file
        ]
    )

def main():
    setup_logging()

    try:
        asyncio.run(amain())
    except KeyboardInterrupt:
        logging.info("Server shutting down...")
    except Exception as e:
        logging.error(f"Unexpected error: {e}")

if __name__ == '__main__':
    main()