@echo off
title Recon Tools V3

:mainmenu
cls
echo -----------  ------------ ------------   --------   ----    ----   ------------   --------     --------   ----         ------------
echo ***********  ************ ************  **********  *****   ****   ************  **********   **********  ****         ************
echo ----    ---  ----         ---          ----    ---- ------  ----   ------------ ----    ---- ----    ---- ----         ----
echo *********    ************ ***          ***      *** ************       ****     ***      *** ***      *** ****         ************
echo ---------    ------------ ---          ---      --- ------------       ----     ---      --- ---      --- ----         ------------
echo ****  ****   ****         ***          ****    **** ****  ******       ****     ****    **** ****    **** ************        *****
echo ----   ----  ------------ ------------  ----------  ----   -----       ----      ----------   ----------  ------------ ------------
echo ****    **** ************ ************   ********   ****    ****       ****       ********     ********   ************ ************
echo                                                       ooooo  0000   0000000      
echo                                                        888    88         888      
echo                                                         888  88       88888       
echo                                                          88888           888    
echo                                                           888       0000000
echo ===================================================================================================================================
echo                                                                  by RXCER
echo ===============================================
echo                  Recon Tools
echo ===============================================
echo 1. Network Scanning Options
echo 2. Lookup Options
echo 3. Local Network Options
echo 4. Exit
echo ===============================================
set /p choice="Enter your choice: "

if "%choice%"=="1" (
    call :scanmenu
) else if "%choice%"=="2" (
    call :lookupmenu
) else if "%choice%"=="3" (
    call :localmenu
) else if "%choice%"=="4" (
    exit
) else (
    echo Invalid choice, please try again.
    pause
    goto mainmenu
)

pause
exit

:scanmenu
cls
echo ===============================================
echo          Network Scanning Options
echo ===============================================
echo 1. DNS Lookup + Cloudflare Detector
echo 2. Zone Transfer
echo 3. Port Scan
echo 4. HTTP Header Grabber
echo 5. Honeypot Detector
echo 6. Robots.txt Scanner
echo 7. Link Grabber
echo 8. Traceroute
echo 9. Grab Banners
echo 10. Subnet Calculator
echo 11. Sub-Domain Scanner
echo 12. Error Based SQLi Scanner
echo 13. Bloggers View
echo 14. Wordpress Scan
echo 15. Crawler
echo 16. MX Lookup
echo 17. Scan All
echo 18. Back to Main Menu
echo ===============================================
set /p choice="Enter your choice: "

if "%choice%"=="1" (
    call :dnslookup
) else if "%choice%"=="2" (
    call :zonetransfer
) else if "%choice%"=="3" (
    call :portscan
) else if "%choice%"=="4" (
    call :httpheader
) else if "%choice%"=="5" (
    call :honeypot
) else if "%choice%"=="6" (
    call :robotstxt
) else if "%choice%"=="7" (
    call :linkgrabber
) else if "%choice%"=="8" (
    call :traceroute
) else if "%choice%"=="9" (
    call :grabbanners
) else if "%choice%"=="10" (
    call :subnetcalc
) else if "%choice%"=="11" (
    call :subdomainscanner
) else if "%choice%"=="12" (
    call :sqliscanner
) else if "%choice%"=="13" (
    call :bloggersview
) else if "%choice%"=="14" (
    call :wordpressscan
) else if "%choice%"=="15" (
    call :crawler
) else if "%choice%"=="16" (
    call :mxlookup
) else if "%choice%"=="17" (
    call :scanall
) else if "%choice%"=="18" (
    goto mainmenu
) else (
    echo Invalid choice, please try again.
    pause
    goto scanmenu
)

pause
goto mainmenu

:lookupmenu
cls
echo ===============================================
echo              Lookup Options
echo ===============================================
echo 1. WHOIS Lookup
echo 2. IP Location Finder
echo 3. Back to Main Menu
echo ===============================================
set /p choice="Enter your choice: "

if "%choice%"=="1" (
    call :whoislookup
) else if "%choice%"=="2" (
    call :iplocator
) else if "%choice%"=="3" (
    goto mainmenu
) else (
    echo Invalid choice, please try again.
    pause
    goto lookupmenu
)

pause
goto mainmenu

:localmenu
cls
echo ===============================================
echo            Local Network Options
echo ===============================================
echo 1. Scan your local network
echo 2. Back to Main Menu
echo ===============================================
set /p choice="Enter your choice: "

if "%choice%"=="1" (
    call :localscan
) else if "%choice%"=="2" (
    goto mainmenu
) else (
    echo Invalid choice, please try again.
    pause
    goto localmenu
)

pause
goto mainmenu

:whoislookup
cls
echo ===============================================
echo               WHOIS Lookup
echo ===============================================
set /p target="Enter the domain for WHOIS lookup: "
echo Performing WHOIS lookup for %target%...
whois %target%
pause
goto lookupmenu

:dnslookup
cls
echo ===============================================
echo        DNS Lookup + Cloudflare Detector
echo ===============================================
set /p target="Enter the domain for DNS lookup: "
echo Performing DNS lookup for %target%...
nslookup %target%
echo Detecting Cloudflare...
nslookup -type=txt %target%
pause
goto scanmenu

:zonetransfer
cls
echo ===============================================
echo              Zone Transfer
echo ===============================================
set /p target="Enter the domain for Zone Transfer: "
echo Attempting Zone Transfer for %target%...
nslookup -type=any %target%
pause
goto scanmenu

:portscan
cls
echo ===============================================
echo               Port Scan
echo ===============================================
set /p target="Enter the IP address for port scanning: "
echo Performing port scan on %target%...
nmap %target%
pause
goto scanmenu

:httpheader
cls
echo ===============================================
echo            HTTP Header Grabber
echo ===============================================
set /p target="Enter the URL to grab HTTP headers: "
echo Grabbing HTTP headers for %target%...
curl -I %target%
pause
goto scanmenu

:honeypot
cls
echo ===============================================
echo              Honeypot Detector
echo ===============================================
set /p target="Enter the IP address to detect Honeypot: "
echo Detecting Honeypot for %target%...
nmap -sV --script=http-enum %target%
pause
goto scanmenu

:robotstxt
cls
echo ===============================================
echo             Robots.txt Scanner
echo ===============================================
set /p target="Enter the domain to scan for robots.txt: "
echo Scanning for robots.txt on %target%...
curl %target%/robots.txt
pause
goto scanmenu

:linkgrabber
cls
echo ===============================================
echo               Link Grabber
echo ===============================================
set /p target="Enter the URL to grab links from: "
echo Grabbing links from %target%...
curl -s %target% | findstr "href="
pause
goto scanmenu

:iplocator
cls
echo ===============================================
echo            IP Location Finder
echo ===============================================
set /p target="Enter the IP address for location lookup: "
echo Finding location for %target%...
curl http://ipinfo.io/%target%
pause
goto lookupmenu

:traceroute
cls
echo ===============================================
echo               Traceroute
echo ===============================================
set /p target="Enter the domain or IP for traceroute: "
echo Performing traceroute to %target%...
tracert %target%
pause
goto scanmenu

:grabbanners
cls
echo ===============================================
echo              Grab Banners
echo ===============================================
set /p target="Enter the IP address to grab banners: "
echo Grabbing banners for %target%...
nmap -sV %target%
pause
goto scanmenu

:subnetcalc
cls
echo ===============================================
echo            Subnet Calculator
echo ===============================================
set /p target="Enter the IP address and subnet mask (e.g., 192.168.1.0/24): "
echo Calculating subnet for %target%...
nmap -sL %target%
pause
goto scanmenu

:subdomainscanner
cls
echo ===============================================
echo         Sub-Domain Scanner
echo ===============================================
set /p target="Enter the domain to scan for sub-domains: "
echo Scanning sub-domains for %target%...
nslookup -type=ns %target%
pause
goto scanmenu

:sqliscanner
cls
echo ===============================================
echo        Error Based SQLi Scanner
echo ===============================================
set /p target="Enter the URL to scan for SQL injection: "
echo Scanning for SQL injection vulnerabilities in %target%...
sqlmap -u %target% --batch --level=5 --risk=3
pause
goto scanmenu

:bloggersview
cls
echo ===============================================
echo             Bloggers View
echo ===============================================
set /p target="Enter the URL to analyze: "
echo Getting HTTP response code for %target%...
curl -I %target%
echo Getting site title for %target%...
curl -s %target% | findstr /i "<title>"
echo Getting Alexa ranking for %target%...
curl http://data.alexa.com/data?cli=10&dat=s&url=%target% | findstr "<REACH RANK="
echo Getting domain authority for %target%...
curl -H "Content-Type: application/json" -d '{"site": "%target%"}' https://api.moz.com/v2/metrics
echo Getting page authority for %target%...
curl -H "Content-Type: application/json" -d '{"site": "%target%"}' https://api.moz.com/v2/metrics
echo Extracting social links from %target%...
curl -s %target% | findstr /i "facebook.com\|twitter.com\|linkedin.com"
pause
goto scanmenu

:wordpressscan
cls
echo ===============================================
echo             Wordpress Scan
echo ===============================================
set /p target="Enter the Wordpress site URL: "
echo Scanning for sensitive files on %target%...
wpscan --url %target% --enumerate vp
echo Detecting Wordpress version on %target%...
wpscan --url %target% --detect-version
echo Scanning for vulnerabilities based on detected version of %target%...
wpscan --url %target% --enumerate vp --plugins-detection aggressive
pause
goto scanmenu

:crawler
cls
echo ===============================================
echo                  Crawler
echo ===============================================
set /p target="Enter the URL to crawl: "
echo Crawling %target%...
curl %target%
pause
goto scanmenu

:mxlookup
cls
echo ===============================================
echo                MX Lookup
echo ===============================================
set /p target="Enter the domain for MX lookup: "
echo Performing MX lookup for %target%...
nslookup -type=mx %target%
pause
goto scanmenu

:phonelookup
cls
echo ===============================================
echo              Phone Lookup
echo ===============================================
set /p target="Enter the phone number to lookup: "
echo Performing phone lookup for %target%...
echo (Insert phone lookup command here)
pause
goto lookupmenu

:usernamelookup
cls
echo ===============================================
echo             Username Lookup
echo ===============================================
set /p target="Enter the username to lookup: "
echo Performing username lookup for %target%...
python C:\Users\harve\theHarvester\theHarvester.py -d %target% -b all
pause
goto lookupmenu

:namelookup
cls
echo ===============================================
echo                Name Lookup
echo ===============================================
set /p target="Enter the name to lookup: "
echo Performing name lookup for %target%...
echo (Insert name lookup command here)
pause
goto lookupmenu

:scanall
cls
echo ===============================================
echo                Scan All
echo ===============================================
set /p target="Enter the domain or IP for full scan: "
echo Performing WHOIS lookup for %target%...
whois %target%
echo Performing DNS lookup for %target%...
nslookup %target%
echo Detecting Cloudflare...
nslookup -type=txt %target%
echo Attempting Zone Transfer for %target%...
nslookup -type=any %target%
echo Performing port scan on %target%...
nmap %target%
echo Grabbing HTTP headers for %target%...
curl -I %target%
echo Detecting Honeypot for %target%...
nmap -sV --script=http-enum %target%
echo Scanning for robots.txt on %target%...
curl %target%/robots.txt
echo Grabbing links from %target%...
curl -s %target% | findstr "href="
echo Finding location for %target%...
curl http://ipinfo.io/%target%
echo Performing traceroute to %target%...
tracert %target%
echo Grabbing banners for %target%...
nmap -sV %target%
echo Calculating subnet for %target%...
nmap -sL %target%
echo Scanning sub-domains for %target%...
nslookup -type=ns %target%
echo Performing reverse IP lookup for %target%...
nslookup %target%
echo Scanning for SQL injection vulnerabilities in %target%...
sqlmap -u %target% --batch --level=5 --risk=3
echo Getting HTTP response code for %target%...
curl -I %target%
echo Getting site title for %target%...
curl -s %target% | findstr /i "<title>"
echo Getting Alexa ranking for %target%...
curl http://data.alexa.com/data?cli=10&dat=s&url=%target% | findstr "<REACH RANK="
echo Getting domain authority for %target%...
curl -H "Content-Type: application/json" -d '{"site": "%target%"}' https://api.moz.com/v2/metrics
echo Getting page authority for %target%...
curl -H "Content-Type: application/json" -d '{"site": "%target%"}' https://api.moz.com/v2/metrics
echo Extracting social links from %target%...
curl -s %target% | findstr /i "facebook.com\|twitter.com\|linkedin.com"
echo Scanning for sensitive files on %target%...
wpscan --url %target% --enumerate vp
echo Detecting Wordpress version on %target%...
wpscan --url %target% --detect-version
echo Scanning for vulnerabilities based on detected version of %target%...
wpscan --url %target% --enumerate vp --plugins-detection aggressive
echo Crawling %target%...
curl %target%
echo Performing MX lookup for %target%...
nslookup -type=mx %target%
pause
goto scanmenu

:localscan
cls
echo ===============================================
echo            Scan Local Network
echo ===============================================
echo Scanning local network...
nmap -sn 192.168.1.0/24
pause
goto localmenu