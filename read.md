Type: MX
Host: @
Points to: mail.datas.world
Priority: 10

b. A (Address) record for the mail subdomain:

Type: A
Host: mail
Points to: 8.222.224.172 

c. SPF (Sender Policy Framework) record:

Type: TXT
Host: @
Value: "v=spf1 mx -all"

d. DMARC record:

Type: TXT
Host: _dmarc
Value: "v=DMARC1; p=quarantine; rua=mailto:admin@datas.world"


Verify the SMTP server is running:
Copyps aux | grep python
Look for a process running your app.py. If you don't see it, the SMTP server isn't running.
Check if anything is listening on port 465:
Copysudo netstat -tuln | grep :465
If you see no output, nothing is listening on that port.
Review your app.py to ensure it's set up to use port 465. Look for a line like:
pythonCopyport = int(os.getenv('PORT', 465))

Check your firewall settings:
Copysudo ufw status
Ensure that port 465 is allowed.
Try running your SMTP server (app.py) with more verbose logging. Add these lines near the top of your app.py:
pythonCopyimport logging
logging.basicConfig(level=logging.DEBUG)
Then run your app.py again and check the output for any errors.
Verify that your .env file has the correct HOSTNAME and PORT settings:
Copycat .env | grep -E "HOSTNAME|PORT"

Try connecting to the SMTP server locally to rule out network issues:
Copytelnet localhost 465
If this connects, your server is running but might not be accessible externally.
Check if the server is binding to the correct interface. In your app.py, ensure you're binding to '0.0.0.0' instead of 'localhost' or '127.0.0.1'.



ls -l /home/engli/proj/mails/datas.world.crt /home/engli/proj/mails/datas.world.key




First, let's verify that the SSL certificate and key files exist and have the correct permissions. Run these commands and provide the output:
Copyls -l /path/to/your/certificate.pem /path/to/your/key.pem

Check if the SMTP server process is actually running and listening on the correct port:
sudo netstat -tlnp | grep :465

Verify that your firewall is allowing connections on port 465:
Copysudo ufw status



Change the permissions of the key file to be more secure:
sudo chmod 600 /home/engli/proj/mails/datas.world.key

Change the ownership of both files to the user that the SMTP server runs as (probably root if you're using sudo):
sudo chown root:root /home/engli/proj/mails/datas.world.crt /home/engli/proj/mails/datas.world.key

Update your .env file to use the full paths to these files:
CopyTLS_CERT_FILE=/home/engli/proj/mails/datas.world.crt
TLS_KEY_FILE=/home/engli/proj/mails/datas.world.ke
