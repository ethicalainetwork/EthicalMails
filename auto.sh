pip install cryptography
pip install python-dotenv secure-smtpd dnspython
pip install pyasyncore 
pip install aiosmtpd
sudo hostnamectl set-hostname mail.datas.world
#openssl s_client -connect mail.datas.world:465 -starttls smtp


sudo apt update
sudo apt install firewalld
sudo systemctl enable firewalld
sudo systemctl start firewalld
sudo firewall-cmd --state ## to check the status 

sudo systemct status firewalld

pip install pyOpenSSL