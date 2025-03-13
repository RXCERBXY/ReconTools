This is my first time at making a reconniassance themed batch file.
Please expect some imperfections and/or errors as this is my first time making something like this with such functionality.

This repo contains both a Batch file (.bat for windows) and a php file (.php for anything else)

I hold no responsibility if you decide to do something unethical with the information you gather from using this batch file. Be careful with what you do if you do anything with the information. It's illegal if you don't get consent from the person before you use such information for penetration testing and such. It's also only illegal if you get caught :)
<br/>
<br/>
<br/>
<br/>
<br/>

Requirements:
-
1: nmap
```
https://nmap.org/download.html
```

2: WHOIS

(Install Chocolatey using windows powershell running as administrator as this was the easiest way for me to install WHOIS)

Choco install command
```
Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))
```
Install command for WHOIS using Choco
```
choco install whois -y
```
Verify that WHOIS has successfully installed
```
whois --version
```
<br/>
<br/>
<br/>
Recon tools is an allrounder batch file with reconniassance and lookup options. It allows you to scan IP Adresses, Domains and your Local Network. It utilises nmap and WHOIS for some of its functionalities, so make sure you have them installed beforehand

It features:
-
- DNS Lookup + Cloudflare Detector

- Zone Transfer

- Port Scan

- HTTP Header Grabber

- Honeypot Detector

- Robots.txt Scanner

- Link Grabber

- Traceroute

- Grab Banners

- Subnet Calculator

- Sub-Domain Scanner

- Error Based SQLi Scanner

- Bloggers View

- Wordpress Scan

- Crawler

- MX Lookup

- WHOIS Lookup

- IP Address Lookup

- Local Network Scan

<br/>

I am planning on adding new features such as:
-
- Username Lookup

- Phone Number Lookup

- Name Lookup

- Email Lookup


<br/>
I got inspiration to do this from using other Recon Tools like REDHAWK and ReconDog. Go check them out and support their projects

ReconDog:
```
https://github.com/s0md3v/ReconDog
```

RED HAWK:
```
https://github.com/Tuhinshubhra/RED_HAWK
```
