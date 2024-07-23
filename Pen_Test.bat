@echo off
setlocal

:menu
cls
echo ==========================
echo Penetration Testing Menu
echo ==========================
echo 1. Scan Options
echo 2. Local Network
echo 3. Exit
echo ==========================
set /p choice="Enter your choice (1-3): "

if "%choice%"=="1" goto scan_options
if "%choice%"=="2" goto local_network_menu
if "%choice%"=="3" goto end

echo Invalid choice. Please try again.
pause
goto menu

:scan_options
cls
echo ==========================
echo Scan Options Menu
echo ==========================
echo 1. Ping a host
echo 2. Port scan (nmap)
echo 3. Perform Traceroute
echo 4. WHOIS lookup
echo 5. Back to Main Menu
echo ==========================
set /p scan_choice="Enter your choice (1-5): "

if "%scan_choice%"=="1" goto ping
if "%scan_choice%"=="2" goto nmap_scan
if "%scan_choice%"=="3" goto traceroute
if "%scan_choice%"=="4" goto whois_lookup
if "%scan_choice%"=="5" goto menu

echo Invalid choice. Please try again.
pause
goto scan_options

:local_network_menu
cls
echo ==========================
echo Local Network Menu
echo ==========================
echo 1. Scan your local network
echo 2. Back to Main Menu
echo ==========================
set /p local_choice="Enter your choice (1-2): "

if "%local_choice%"=="1" goto local_network_scan
if "%local_choice%"=="2" goto menu

echo Invalid choice. Please try again.
pause
goto local_network_menu

:ping
set /p target="Enter the domain or IP to ping: "
echo Pinging %target%
ping %target%
pause
goto scan_options

:nmap_scan
set /p target="Enter the domain or IP to scan with nmap: "
echo Checking open ports on %target% using nmap
nmap %target%
pause
goto scan_options

:traceroute
set /p target="Enter the domain or IP to traceroute: "
echo Performing traceroute to %target%
tracert %target%
pause
goto scan_options

:whois_lookup
set /p target="Enter the domain to perform WHOIS lookup: "
echo Performing WHOIS lookup for %target%
whois %target%
pause
goto scan_options

:local_network_scan
echo Scanning your local network using nmap
nmap -sn 192.168.1.0/24
pause
goto local_network_menu

:end
echo Exiting...
pause
endlocal
exit