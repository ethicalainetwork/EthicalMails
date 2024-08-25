import os
import subprocess
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from datetime import datetime, timedelta

def generate_self_signed_cert(domain, email):
    # Generate our key
    key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Generate a CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])).add_extension(
        x509.SubjectAlternativeName([
            x509.DNSName(domain),
            x509.DNSName(f"mail.{domain}"),
        ]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Generate a self-signed cert
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"My Organization"),
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
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
        x509.SubjectAlternativeName([x509.DNSName(domain)]),
        critical=False,
    ).sign(key, hashes.SHA256())

    # Write our key and certificate out
    with open(f"{domain}.key", "wb") as f:
        f.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    with open(f"{domain}.crt", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))

    print(f"Generated self-signed certificate for {domain}")

def setup_env_file(domain, email):
    env_content = f"""# SMTP Server Configuration
HOSTNAME=0.0.0.0
DOMAIN={domain}
PORT=25

# Security
USE_TLS=true
TLS_CERT_FILE={domain}.crt
TLS_KEY_FILE={domain}.key

# Authentication
REQUIRE_AUTH=true
AUTH_USERNAME={email}
AUTH_PASSWORD=your_secure_password

# Logging
LOG_LEVEL=INFO
LOG_FILE=/var/log/smtp_server.log

# Mail handling
MAX_MESSAGE_SIZE=10485760  # 10 MB
RELAY_DOMAINS={domain}

# Anti-spam (basic)
MAX_RECIPIENTS=50
BLACKLISTED_IPS=

# Performance
MAX_CONNECTIONS=100
TIMEOUT=60
"""

    with open(".env", "w") as f:
        f.write(env_content)

    print(f"Generated .env file with configuration for {domain}")

def setup_dns_records(domain):
    print(f"\nTo set up DNS records for {domain}, add the following records to your DNS configuration:")
    print(f"1. MX record:")
    print(f"   mail.{domain}. IN MX 10 mail.{domain}.")
    print(f"2. A record for the mail subdomain:")
    print(f"   mail.{domain}. IN A <Your-Server-IP>")
    print("3. SPF record (helps prevent email spoofing):")
    print(f'   {domain}. IN TXT "v=spf1 mx -all"')
    print("4. DKIM record (you'll need to set this up separately with your email server)")
    print("5. DMARC record:")
    print(f'   _dmarc.{domain}. IN TXT "v=DMARC1; p=quarantine; rua=mailto:admin@{domain}"')

def main():
    domain = "datas.world"
    email = "admin@datas.world"

    generate_self_signed_cert(domain, email)
    setup_env_file(domain, email)
    setup_dns_records(domain)

    print("\nSetup complete!")
    print("Remember to update the paths in the .env file to match your actual certificate locations.")
    print("Also, make sure to set a strong password for AUTH_PASSWORD in the .env file.")

if __name__ == "__main__":
    main()