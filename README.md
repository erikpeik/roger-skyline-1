# roger-skyline-1

This subject aims to initiate you to the basics of system and network administration.

This second project, roger-skyline-1 let you install a Virtual Machine, and discover the basics of system and network administration as well as a lot of services used on a server machine.

- [Installing Virtual Machine](#installing-virtual-machine)
- [Added rights to sudo](#added-rights-to-sudo)
- [Configuring static IP and a Netmask in \30](#configuring-static-ip-and-a-netmask-in-30)
- [How to change the SSH port](#how-to-change-the-ssh-port)
- [Adding banner art when logging in](#adding-banner-art-when-logging-in)
- [SSH access with public keys](#ssh-access-with-public-keys)
- [Setup a Firewall](#setup-a-firewall)
- [Set a DoS protection](#set-a-dos-protection)
- [Protecting against port scans](#protecting-against-port-scans)
- [Disable unnecessary services](#disable-unnecessary-services)
- [A script that updates all the packages](#a-script-that-updates-all-the-packages)
- [Monitor crontab changes](#monitor-crontab-changes)
- [Web Part](#web-part)
- [Creating a self-signed SSL](#creating-a-self-signed-ssl)
- [Testing DoS with slowloris attack to Apache server](#testing-dos-with-slowloris-attack-to-apache-server)
- [Deployment script](#deployment-script)

## Installing Virtual Machine

I used Debian like we did use in the last project [init](https://github.com/erikpeik/init).

To create a 4.2 GB partition you have to calculate it with some kind of Gigabytes to Bytes converter.

Personally used this: [https://convertlive.com/u/convert/gigabytes/to/bytes#4.2](https://convertlive.com/u/convert/gigabytes/to/bytes#4.2)

> ****4.2 Gigabytes = 4509715660.8 Bytes****
> 

To check disk size you can use the command: `sudo fdisk -l`

<img width="570" alt="Untitled" src="https://user-images.githubusercontent.com/52178013/168657501-4901c22b-4b6b-4c9f-bbd2-e2fb7ef88c12.png">

Didn’t install any predefined collections of software. Installed first just plain Debian and added stuff later on.

## Added rights to sudo

Added sudoers rights with editing `/etc/sudoers`

```bash
> sudo vim /etc/sudoers

# User privilege specification
root   ALL=(ALL:ALL) ALL
emende ALL=(ALL:ALL) ALL
```

## Configuring static IP and a Netmask in \30

This tutorial helped to go through this part: **[How to set up static IP address on Debian Linux 10/11](https://www.cyberciti.biz/faq/add-configure-set-up-static-ip-address-on-debianlinux/)**

To display available Ethernet network interfaces `ip -c link show`

<img width="942" alt="Untitled 1" src="https://user-images.githubusercontent.com/52178013/168657537-743bf93a-dab8-4510-b96f-5906ddfc5630.png">


Note down the interface name and type the following command to see the current IP address assigned to that network interface: `ip -c addr show enp0s3`

<img width="832" alt="Untitled 2" src="https://user-images.githubusercontent.com/52178013/168657556-ddc43541-4bda-4bb1-a95f-b1b405765b26.png">

In VirtualBox settings you have to change the network from NAT to Bridged Adapter:

<img width="652" alt="Untitled 3" src="https://user-images.githubusercontent.com/52178013/168657581-61855d1f-e826-4fc6-8381-2590a80ca89d.png">

`/etc/network/interfaces` contain network interface configuration information for Debian.

Firstly looked to the primary network interface enp0s3:

```bash
# The primary network interface
allow-hotplug enp0s3
iface enp0s3 inet dhcp
```

Removed allow-hotplug and iface lines with just only `auto enp0s3`

The output should look something like this:

```bash
# The primary network interface
auto enp0s3
```

Then you have to make a new file, for example: `sudo touch /etc/network/interfaces.d/enp0s3`

This is what that file should contain:

```visual-basic
iface enp0s3 inet static
address 10.12.254.101
netmask 255.255.255.252
gateway 10.12.254.254
```

To calculate your subnet used this calculator: [https://www.calculator.net/ip-subnet-calculator.html](https://www.calculator.net/ip-subnet-calculator.html)

The subnet mask had to be /30 so the netmask has to be `255.255.255.252`

The gateway value you can get from MAC using:

```visual-basic
> ipconfig getoption en0 router
10.12.254.254
```

With that information you can use IPv4 Subnet Calculator provided previously:

<img width="754" alt="Untitled 4" src="https://user-images.githubusercontent.com/52178013/168657640-4d84e916-c5cd-4685-9a3c-d507ef7dd437.png">

You can choose pretty much anything that you want, I did just choose `10.12.254.101`

To restart networking you can run `sudo systemctl restart networking`

<aside>
💡 Do not run restart over ssh session as you will disconnect.

</aside>

Make sure the service is restarted without any errors. 

You can run `sudo systemctl status networking` to check out if it still active.

The output should look something like this:

<img width="754" alt="Screen_Shot_2022-05-06_at_5 22 57_PM" src="https://user-images.githubusercontent.com/52178013/168657688-2fca10b9-f24e-46b5-9d82-89ff13c4eda6.png">

## How to change the SSH port

To change your SSH port to anything else than 22 you can change that in `/etc/ssh/sshd_config`

First `sudo vim /etc/ssh/sshd_config` and then uncomment line 15 and change the port whatever you want.

It should look something like this:

```bash
#	$OpenBSD: sshd_config,v 1.103 2018/04/09 20:41:22 tj Exp $

# This is the sshd server system-wide configuration file.  See
# sshd_config(5) for more information.

# This sshd was compiled with PATH=/usr/bin:/bin:/usr/sbin:/sbin

# The strategy used for options in the default sshd_config shipped with
# OpenSSH is to specify options with their default value where
# possible, but leave them commented.  Uncommented options override the
# default value.

Include /etc/ssh/sshd_config.d/*.conf

Port 8101
#AddressFamily any
#ListenAddress 0.0.0.0
#ListenAddress ::
```

## Adding banner art when logging in

This part wasn’t really on this subject but found this out with my friend [altikka](https://github.com/reviisori) that suggested that I add this one.

Here is what it’s going to look like:

![banner-gif](https://user-images.githubusercontent.com/52178013/168657718-cf07d9f6-3eef-4286-b9f7-577388927392.gif)

How this is done is just changing the Message of the day (usually called motd)

Used this site to get those cool ASCII arts: [http://patorjk.com/software/taag/](http://patorjk.com/software/taag/)

Edit file `/etc/motd` to look like whatever you want. 

You can type there pretty much anything.  This is what I had in the file:

```markdown
This second project, roger-skyline-1 let you install a Virtual Machine,
and discover the basics of system and network administration
as well as a lot of services used on a server machine.

                                 _          _ _
 _ __ ___   __ _  ___ _ __   ___| | ___   _| (_)_ __   ___
| '__/ _ \ / _` |/ _ \ '__| / __| |/ / | | | | | '_ \ / _ \
| | | (_) | (_| |  __/ |    \__ \   <| |_| | | | | | |  __/
|_|  \___/ \__, |\___|_|    |___/_|\_\\__, |_|_|_| |_|\___|
           |___/                      |___/

        _____ ___  __ _____ __  __ _____ _____
        ||==  || \/ | ||==  ||\\|| ||  ) ||==
        ||___ ||    | ||___ || \|| ||_// ||___
```

## SSH access with public keys

Assuming that you have currently SSH key already made, you can from MAC just use the command `ssh-copy-id emende@10.12.254.101 -p 8101` → `ssh-copy-id user@ip -p port`

<aside>
🔎 **man ssh-copy-id** - use locally available keys to authorise logins on a remote machine

</aside>

Another way is just to copy your public key from Mac `~/.ssh/id_rsa.pub` to your Debian in location `~/.ssh/authorized_keys`

I did the following changes to `/etc/ssh/sshd_config` to remove the password and root authentication:

```xml
34 PermitRootLogin no
39 PubkeyAuthentication yes
42 AuthorizedKeysFile .ssh/authorized_keys .ssh/authorized_keys2
58 PasswordAuthentication no
59 PermitEmptyPasswords no
```

Removed comments from the beginning of those lines above. Some of those settings are by default those values, but at least PermitRootLogin and PasswordAuthentication are changed to **no**.

## Setup a Firewall

First I had to install **UFW** `sudo apt install ufw`

**UFW** stands for **u**ncomplicated **f**ire**w**all and it is basically a firewall configuration tool.

Getting started I read this tutorial about **UWF**:

[UFW Essentials: Common Firewall Rules and Commands](https://www.digitalocean.com/community/tutorials/ufw-essentials-common-firewall-rules-and-commands)

To check if **UFW** is enabled you can run: `sudo ufw status`

if you got a `Status: inactive`, it means your firewall is not enabled. 

To enable **UFW** you can run: `sudo ufw enable`

Setup the following firewall rules:

- SSH: `sudo ufw allow 8101/tcp`
- HTTP: `sudo ufw allow 80/tcp`
- HTTPS: `sudo ufw allow 443`

## Set a DoS protection

What is DoS? (Denial Of Service Attack)

> A **Denial-of-Service (DoS) attack** is an attack meant to shut down a machine or network, making it inaccessible to its intended users. DoS attacks accomplish this by flooding the target with traffic or sending it information that triggers a crash. In both instances, the DoS attack deprives legitimate users (i.e. employees, members, or account holders) of the service or resource they expected.
> 

Source: [https://www.paloaltonetworks.com/cyberpedia/what-is-a-denial-of-service-attack-dos](https://www.paloaltonetworks.com/cyberpedia/what-is-a-denial-of-service-attack-dos)

Proceed with the **Fail2Ban** installation: `sudo apt install fail2ban`

> **Fail2ban** is an intrusion prevention software framework that protects computer servers from brute-force attacks.
> 

Source: [https://en.wikipedia.org/wiki/Fail2ban](https://en.wikipedia.org/wiki/Fail2ban)

Before configuring Fail2Ban make backup of that configuration file:

`sudo cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local`

Things that I modified in `jail.local`:

```bash
[sshd]
mode    = normal
enabled = true
port    = 8101
logpath = %(sshd_log)s
backend = %(sshd_backend)s
maxretry = 3
bantime = 600

# DOS PROTECT
[http-get-dos]
enabled = true
port    = http,https
filter  = http-get-dos
logpath = /var/log/apache2/access.log
maxretry = 300
findtime = 300
bantime = 30
297 action = iptables[name=HTTP, port=http, protocol=tcp]
```

Had to made also new filter for that: `sudo vim /etc/fail2ban/filter.d/https-get-dos.conf`

```bash
[Definition]
failregex = ^<HOST> -.*(GET|POST).*
ignoreregex =
```

After changing the setting run restart: `sudo systemctl restart fail2ban`

To really test this you need to have Apache 2 server set up. More about testing can be found later on
[Testing DoS with slowloris attack to Apache server](#testing-dos-with-slowloris-attack-to-apache-server)

If you want to unban yourself you can try: `sudo fail2ban-client set https-get-dos 10.12.1.4`

## Protecting against port scans

This tutorial translated from French was really useful: [https://en-wiki.ikoula.com/en/To_protect_against_the_scan_of_ports_with_portsentry](https://en-wiki.ikoula.com/en/To_protect_against_the_scan_of_ports_with_portsentry)

Install PortSentry with `sudo apt install portsentry`

The following window will pop up. Just press enter to skip that.

<img width="1261" alt="Untitled 5" src="https://user-images.githubusercontent.com/52178013/168657800-86398119-01d0-4c42-9fd1-9d389290c054.png">

First, we have to set TCP and UDP Advanced mode. You can simply modify `/etc/default/portsentry` by following:

```bash
9 TCP_MODE="atcp"
10 UDP_MODE="audp"
```

Advanced mode means that any port below 1024 (by default) will be monitored. You can find more information by reading `/etc/portsentry/portsentry.conf`

```bash
# This is the number of ports you want PortSentry to monitor in Advanced mode.
# Any port *below* this number will be monitored. Right now it watches
# everything below 1024.

# On many Linux systems you cannot bind above port 61000. This is because
# these ports are used as part of IP masquerading. I don't recommend you
# bind over this number of ports. Realistically: I DON'T RECOMMEND YOU MONITOR
# OVER 1024 PORTS AS YOUR FALSE ALARM RATE WILL ALMOST CERTAINLY RISE. You've been
# warned! Don't write me if you have have a problem because I'll only tell
# you to RTFM and don't run above the first 1024 ports.
```

The next step is to block UDP/TCP scans. You can do that by changing `/etc/portsentry/portsentry.conf`

```bash
BLOCK_UDP="1"
BLOCK_TCP="1"
```

There are many ways to block scans but I did choose iptables that have native Linux support.

To change that you have to comment your current `KILL_ROUTE` and uncomment this line:

```bash
209 KILL_ROUTE="/sbin/iptables -I INPUT -s $TARGET$ -j DROP"
```

You can check that there is only one `KILL_ROUTE` selected with:

`cat /etc/portsentry/portsentry.conf | grep KILL_ROUTE | grep -v "#"`

After changing those settings you can restart PortSentry with the following command: `sudo systemctl restart portsentry`

I used `nmap` to try port scanning unused ports. You might have to install a second Virtual Machine. In Linux installation works like `sudo apt install nmap` or if you use Mac run `brew install nmap`

I did run nmap with the following command: `sudo nmap -PN -sS 10.12.254.101`, but you can try it also without flags if you don’t have sudo rights.

```bash
May 16 20:51:09 debian-emende portsentry[1870]: attackalert: TCP SYN/Normal scan from host: 10.12.1.4/10.12.1.4 to TCP port: 515
May 16 20:51:09 debian-emende portsentry[1870]: attackalert: Host 10.12.1.4 has been blocked via wrappers with string: "ALL: 10.12.1.4 : DENY"
May 16 20:51:09 debian-emende portsentry[1870]: attackalert: Host 10.12.1.4 has been blocked via dropped route using command: "/sbin/iptables -I INPUT -s 10.12.1.4 -j DROP"
```

When you get banned your ssh connection will freeze and you can’t connect it anymore.

You can check also if your IP address is banned via iptables:

```bash
> sudo iptables -L -n -v | head
Chain INPUT (policy ACCEPT 28 packets, 1792 bytes)
 pkts bytes target     prot opt in     out     source               destination         
 8124  494K DROP       all  --  *      *       10.12.1.4            0.0.0.0/0
```

You can delete the entry with: `sudo iptables -D INPUT -s 10.12.1.4 -j DROP`

To finally get ourselves unbanned, we have to delete the IP at the end of`/etc/hosts.deny`, and restart `portsentry` with `sudo systemctl restart portsentry`

## Disable unnecessary services

```bash
sudo systemctl disable console-setup.service 
sudo systemctl disable keyboard-setup.service
sudo systemctl disable apt-daily.timer
sudo systemctl disable apt-daily-upgrade.timer
```

`systemctl list-unit-files --state=enabled` to check all enabled services

## A script that updates all the packages

From now on made a folder `/usr/scripts` where I will store my scripts.

`/usr/scripts/update.sh` looks like this:

```bash
#!/bin/sh

echo -n 'Updating Packages ' >> /var/log/update_script.log
echo `date` >> /var/log/update_script.log
sleep 5
echo `sudo apt-get update --yes` >> /var/log/update_script.log
echo `sudo apt-get upgrade --yes` >> /var/log/update_script.log
echo '' >> /var/log/update_script.log
```

I had to add sleep to this script because sometimes when you restart your computer it cannot connect to Debian servers. 5-second sleep seems to fix things.

When you make the file remember to add executable right with `chmod 755 update.sh`

Used crontab to make it schedulable. `sudo crontab -e` will open a file where you introduce the following two tasks:

```bash
# run update.sh when reboots
@reboot sh /usr/scripts/update.sh

# run update.sh once a week at 4AM (Sunday)
* 4 * * 0 sh /usr/scripts/update.sh
```

A helpful tool is [Crontab Generator](https://crontab-generator.org/), where you can put specific times and it will generate a crontab line.

## Monitor crontab changes

I’m using the `mail` command to send mail to root. If you don't have it you can download it by following command: `sudo apt install mailutils`

The following `monitor.sh` script will diff current crontab with backup that had made previously. If there is any diff it will send mail to root.

```bash
#!/bin/sh

CRONTAB='/var/spool/cron/crontabs/root'
BACKUP='/var/spool/cron/crontabs/root.backup'

DIFF=`diff $CRONTAB $BACKUP`
if [ ! -z "$DIFF" ]; then
	echo "Crontab file has been changed." | mail -s "Crontab modified" root
fi

cp $CRONTAB $BACKUP
```

Add executable rights: `chmod 755 monitor.sh`

To run this script every midnight add the following line to your crontab file:

`0 0 * * * sh /usr/scripts/monitor.sh`

Send mails will appear in `/var/mail` folder. There are specified files for each user’s mails.

**How to setup postfix:**

> Postfix is a free and open-source mail transfer agent (MTA) that routes and delivers electronic mail. [https://en.wikipedia.org/wiki/Postfix_(software)](https://en.wikipedia.org/wiki/Postfix_(software))
> 
1. Install Postfix
    
    You can install postfix with the command: `sudo apt install postfix`
    
2. Changing the Postfix Configuration
    
    Postfix’s configuration settings are defined in the `/etc/postfix/main.cf` file. Rather than editing this file directly, you can use Postfix’s `postconf` command to query or set configuration settings.
    
    - Change the home mailbox directory: `sudo postconf -e "home_mailbox = mail/"`
    - Edit `/etc/aliases` root to be exactly `root: root`
        - `sudo newaliases` will initialize and refresh the alias database.
    - Restart the postfix service `sudo service postfix restart`

**Mutt – A Command Line Email Client to Send Mails from Terminal**

1. Install Mutt
    
    You can install mutt with command: `sudo apt install mutt`
    
2. Create config file `/root/.muttrc` to be:

```bash
set mbox_type=Maildir
set folder="/root/mail"
set mask="!^\\.[^.]"
set mbox="/root/mail"
set record="+.Sent"
set postponed="+.Drafts"
set spoolfile="/root/mail"
```

You can now test if you can send and receive mails by sending: 

`echo "Text" | sudo mail -s "Subject" root`

Type `mutt` to open your mailbox. Enter **q** to exit. 

When opening `mutt` it should look something like this:

<img width="617" alt="Untitled 6" src="https://user-images.githubusercontent.com/52178013/168657877-d3d1e497-070e-44d0-914e-3c7c2d368bf6.png">

You can press **enter** to read that message:

<img width="754" alt="Screen_Shot_2022-05-06_at_5 22 57_PM" src="https://user-images.githubusercontent.com/52178013/168657909-5ba098ca-65af-40b7-ad64-dfebe3bc530f.png">

## Web Part

[Apache](https://httpd.apache.org/) was my choice of service.

1. Installing Apache
    
    `sudo apt update && sudo apt install apache2`
    
2. Checking your webserver status
    
    `sudo systemctl status apache2`
    
    It should look like this:
    
    ```bash
    ● apache2.service - The Apache HTTP Server
         Loaded: loaded (/lib/systemd/system/apache2.service; enabled; vendor preset: enabled)
         Active: active (running) since Fri 2022-05-13 09:52:46 EEST; 1min 57s ago
           Docs: https://httpd.apache.org/docs/2.4/
       Main PID: 4493 (apache2)
          Tasks: 55 (limit: 4678)
         Memory: 21.1M
            CPU: 164ms
         CGroup: /system.slice/apache2.service
                 ├─4493 /usr/sbin/apache2 -k start
                 ├─4494 /usr/sbin/apache2 -k start
                 └─4496 /usr/sbin/apache2 -k start
    
    May 13 09:52:46 debian-emende systemd[1]: Starting The Apache HTTP Server...
    May 13 09:52:46 debian-emende apachectl[4492]: AH00558: apache2: Could not reliably determine the server's fully qualified domain name, using 127.0.1.1. Set the >
    May 13 09:52:46 debian-emende systemd[1]: Started The Apache HTTP Server.
    ```
    
    Change from `/etc/apache2/ports.conf` following lines:
    
    ```bash
    Listen **10.12.254.101:80**
    
    <IfModule ssl_module>
    	Listen **10.12.254.101:443**
    </IfModule>
    
    <IfModule mod_gnutls.c>
    	Listen **10.12.254.101:443**
    </IfModule>
    ```
    
    This will prevent you from Listening to it from [https://localhost](https://localhost). Only [https://10.12.254.101](https://10.12.254.101) will work. You can check this by temporarily installing curl `sudo apt install curl` and trying `curl -k https://localhost`. It should say **Connection refused**.
    
    You can also check if the website is up in a browser. You can find it at [http://10.12.245.101](http://10.12.254.101/) where the address is your IP (same as when connecting to SSH) 
    
    You can pretty much start doing your website in `/var/www/html`. Just replace index.html with your own one and you are done. For example, this is what my website looks like (source code in GitHub):
    
    <img width="599" alt="Untitled 7" src="https://user-images.githubusercontent.com/52178013/168658133-4fd991af-9ba0-425c-8236-74b096d061e1.png">
    
    ## Creating a self-signed SSL
    
    I did use this tutorial to get hang of it: [https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10](https://www.digitalocean.com/community/tutorials/how-to-create-a-self-signed-ssl-certificate-for-apache-in-debian-10)
    
    The following part is mostly copied from there, you can find the same information also there.
    
    **You can create a self-signed key and certificate pair with OpenSSL in a single command:**
    
    `sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout /etc/ssl/private/apache-selfsigned.key -out /etc/ssl/certs/apache-selfsigned.crt`
    
    - **openssl:** Basic command-line tool for creating and managing OpenSSL certificates, keys and other files.
    - **req:** This subcommand specifies that we want to use X.509 certificate signing request (CSR) management. The `X.509` is a public key infrastructure standard that SSL and TSL adhere to for their key and certificate management.
    - **-x509:** This further modifies the previous subcommand by telling the utility that we want to make a self-signed certificate instead of generating a certificate signing request.
    - **-nodes:** This tells OpenSSL to skip the option to secure our certificate with a passphrase. We need Apache to be able to read the file without user intervention when the server starts up. With passphrase, we would have to enter it after every restart.
    - **-days 364:** This option sets the length of time that the certificate will be considered valid.
    - **-newkey rsa:2048:** This specifies that we want to generate a new certificate and a new key at the same time. The `rsa:2048` portion tells it to make an RSA key that is 2048 bits long.
    - **-keyout:** This line tells where to place the generated private key.
    - **-out:** This tells where to place the certificate

The entirety of the prompts will look something like this:

```bash
Generating a RSA private key
...............................................................................................................+++++
...........+++++
writing new private key to '/etc/ssl/private/apache-selfsigned.key'
-----
You are about to be asked to enter information that will be incorporated
into your certificate request.
What you are about to enter is what is called a Distinguished Name or a DN.
There are quite a few fields but you can leave some blank
For some fields there will be a default value,
If you enter '.', the field will be left blank.
-----
Country Name (2 letter code) [AU]:**FI**
State or Province Name (full name) [Some-State]:**Uusimaa**
Locality Name (eg, city) []:**Helsinki**
Organization Name (eg, company) [Internet Widgits Pty Ltd]:**Erik Mende**
Organizational Unit Name (eg, section) []:
Common Name (e.g. server FQDN or YOUR name) []:**10.12.254.101**
Email Address []:**emende@student.hive.fi**
```

**Creating an Apache Configuration Snippet with Strong Encryption Settings**

Create a new snippet to `/etc/apache2/conf-availabele/ssl-paramas.conf` and copy following configuration:

```bash
SSLCipherSuite EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH
SSLProtocol All -SSLv2 -SSLv3 -TLSv1 -TLSv1.1
SSLHonorCipherOrder On
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
# Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Frame-Options DENY
Header always set X-Content-Type-Options nosniff
# Requires Apache >= 2.4
SSLCompression off
SSLUseStapling on
SSLStaplingCache "shmcb:logs/stapling-cache(150000)"
# Requires Apache >= 2.4.11
SSLSessionTickets Off
```

**Modifying the Default Apache SSL Virtual Host File**

Before modifying the file take backup of the original SSL Virtual Host file:

`sudo cp /etc/apache2/sites-available/default-ssl.conf /etc/apache2/sites-available/default-ssl.conf.backup`

Now open SSL Virtual Host file to make the adjustments:

`sudo vim /etc/apache2/sites-available/default-ssl.conf`

This is what the file looks like by default:

```bash
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin webmaster@localhost

		DocumentRoot /var/www/html

		...

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

    ...

		SSLEngine on

		...

		SSLCertificateFile	/etc/ssl/certs/ssl-cert-snakeoil.pem
		SSLCertificateKeyFile /etc/ssl/private/ssl-cert-snakeoil.key

		...

		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>

		...

	</VirtualHost>
</IfModule>
```

After making changes it should look more like this: **(bold text is what is modified)**

```bash
<IfModule mod_ssl.c>
	<VirtualHost _default_:443>
		ServerAdmin **emende@student.hive.fi**
		**ServerName 10.12.254.101**

		DocumentRoot /var/www/html

		...

		ErrorLog ${APACHE_LOG_DIR}/error.log
		CustomLog ${APACHE_LOG_DIR}/access.log combined

    ...

		SSLEngine on

		...

		SSLCertificateFile	/etc/ssl/certs/**apache-selfsigned.crt**
		SSLCertificateKeyFile /etc/ssl/private/**apache-selfsigned.key**

		...

		<FilesMatch "\.(cgi|shtml|phtml|php)$">
				SSLOptions +StdEnvVars
		</FilesMatch>
		<Directory /usr/lib/cgi-bin>
				SSLOptions +StdEnvVars
		</Directory>

		...

	</VirtualHost>
</IfModule>
```

You can also modify the HTTP Host File to Redirect to HTTPS. Inside `/etc/apache2/sites-available/000-default.conf` add a `Redirect` directive, pointing all traffic to the SSL version of the site:

```bash
<VirtualHost *:80>

        ...

        Redirect "/" "https://10.12.254.101/"

        ...

</VirtualHost>
```

**Enabling the Changes in Apache**

Enable `mod_ssl` (the Apache SSL module) and `mod_headers`, which is needed by some of the settings in our SSL snippet:

```bash
sudo a2enmod ssl
sudo a2enmod headers
```

Next, enable your SSL VirtualHost with the `a2ensite` command:

```bash
sudo a2ensite default-ssl
```

You will also need to enable your `ssl-params.conf` file, to read in the values you’ve set:

```bash
sudo a2enconf ssl-params
```

You can check that there are no syntax errors in our files, by typing:

```bash
sudo apache2ctl configtest
```

As long as your output has `Syntax OK` in it you are good to go. Now you can restart Apache to implement the changes: `sudo systemctl restart apache2`

**Testing Encryption**

Open the browser and type `https://` following your server’s IP. Mine is [https://10.12.254.101/](https://10.12.254.101/)

Because the certificate isn’t signed by one of your browser’s trusted certificate authorities, you will likely see a scary looking warning like the one below:

<img width="643" alt="Untitled 8" src="https://user-images.githubusercontent.com/52178013/168657994-05bf8f80-3456-41ce-a8f5-e7bee9d1775c.png">

Click the **Advanced** and continue to proceed to your website:

![Untitled 9](https://user-images.githubusercontent.com/52178013/168658010-351857ab-43bb-435e-baf6-8bda85cba826.png)

If everything works as it should you can change the redirect to permanent redirect by opening the same file as before: `sudo vim /etc/apache2/sites-available/000-default.conf`

```bash
<VirtualHost *:80>
        . . .

        Redirect permanent "/" "https://10.12.254.101/"

        . . .
</VirtualHost>
```

Check your syntax error with `sudo apache2ctl configtest` and if everything works then restart Apache: `sudo systemctl restart apache2`

Now you have configured your Apache server to use strong encryption for client connections. This will allow you to serve requests securely and will prevent outside parties from reading your traffic

## Testing DoS with slowloris attack to Apache server

Now when you have a Web Server running is a good time to try to attack it simple python script [slowloris](https://github.com/gkbrk/slowloris) that you can find on the internet.

> Slowloris is basically an HTTP Denial of Service attack that affects threaded servers. [https://github.com/gkbrk/slowloris](https://github.com/gkbrk/slowloris)
> 

Basically, it sends lots of HTTP request frequently that exhausts the servers thread pool and the server can't reply to other people

You can install slowloris on any machine that has python & pip installed. 

Steps on how to send an attack to your own Web Server:

- Install slowloris by typing `sudo pip3 install slowloris`
- Start attack with `python3 slowloris.py 10.12.254.101`

```bash
> python3 slowloris.py 10.12.254.101
[13-05-2022 20:22:25] Attacking 10.12.254.101 with 150 sockets.
[13-05-2022 20:22:25] Creating sockets...
[13-05-2022 20:22:25] Sending keep-alive headers... Socket count: 150
[13-05-2022 20:22:40] Sending keep-alive headers... Socket count: 150
```

- If the socket count is not 150 from the beginning, it means that the attack is not effective or the server is down.
- After a while socket count goes to 0

```bash
[13-05-2022 20:25:25] Sending keep-alive headers... Socket count: 150
[13-05-2022 20:25:40] Sending keep-alive headers... Socket count: 67
[13-05-2022 20:25:55] Sending keep-alive headers... Socket count: 0
[13-05-2022 20:26:10] Sending keep-alive headers... Socket count: 0
[13-05-2022 20:26:25] Sending keep-alive headers... Socket count: 0
```

- You can check if you have been banned with the command: `sudo fail2ban-client status http-get-dos`

```bash
Status for the jail: http-get-dos
|- Filter
|  |- Currently failed:	1
|  |- Total failed:	1835
|  `- File list:	/var/log/apache2/access.log
`- Actions
   |- **Currently banned:	1**
   |- Total banned:	5
   `- **Banned IP list:	10.12.1.4**
```

- In log file `/var/log/apache2/access.log` you can see all HTTP requests that have come through.

You can unban with the command `sudo fail2ban-client set http-get-dos unbanip 10.12.1.4`

**Bellow is also an example video about this scenario:**

[https://user-images.githubusercontent.com/52178013/168333267-4c22530e-c18a-4bf1-ba29-b22281f37929.mp4](https://user-images.githubusercontent.com/52178013/168333267-4c22530e-c18a-4bf1-ba29-b22281f37929.mp4)

## Deployment script

This part idea was to propose a functional solution for deployment automation. Deployment in software and web development means pushing changes or updates from one deployment environment to another. In this case from the local directory to the server. 

There are multiple ways to do this but I just used a basic shell script:

```bash
RED="\e[31m"
GREEN="\e[32m"
ENDCOLOR="\e[0m"

WEB_DIR='/var/www/html'
DEPLOY_DIR='/usr/scripts/deployment'

DIFF=`diff -q $DEPLOY_DIR $WEB_DIR`

if [ ! -z "$DIFF" ]; then
	OUTPUT=$(sudo cp -v $DEPLOY_DIR/* $WEB_DIR)
	echo "New version deployed. $(date)
$DIFF
Changed files:
$OUTPUT" | mail -s "New version deployed" root

	echo "${GREEN}New version deployed. $(date)"
	echo "${ENDCOLOR}$DIFF"
	echo "Changed files:"
	echo "$OUTPUT"
else
	echo "${RED}No files changed. Newest version deployed.${ENDCOLOR}"
fi
```

Here we are using again diff to see if there is any change between the two paths. If so then we are copying everything from the deployment directory to Apache. Sending mail to root and scheduled this with crontab 4AM every day: `0 4 * * * sh /usr/scripts/deployment.sh`
