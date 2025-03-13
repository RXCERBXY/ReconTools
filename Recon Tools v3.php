<?php

//Clear screen functions
function clearScreen() {
    if (strtoupper(substr(PHP_OS, 0, 3)) === 'WIN') {
        system('cls');
    }else{
        system('clear');
    }
}

// Function to display the main menu
function mainMenu() {
    clearScreen();
    echo "-----------  ------------ ------------   --------   ----    ----   ------------   --------     --------   ----         ------------\n";
    echo "***********  ************ ************  **********  *****   ****   ************  **********   **********  ****         ************\n";
    echo "----    ---  ----         ---          ----    ---- ------  ----   ------------ ----    ---- ----    ---- ----         ----\n";
    echo "*********    ************ ***          ***      *** ************       ****     ***      *** ***      *** ****         ************\n";
    echo "---------    ------------ ---          ---      --- ------------       ----     ---      --- ---      --- ----         ------------\n";
    echo "****  ****   ****         ***          ****    **** ****  ******       ****     ****    **** ****    **** ************        *****\n";
    echo "----   ----  ------------ ------------  ----------  ----   -----       ----      ----------   ----------  ------------ ------------\n";
    echo "****    **** ************ ************   ********   ****    ****       ****       ********     ********   ************ ************\n";
    echo "                                                       ooooo  0000   0000000      \n";
    echo "                                                        888    88         888      \n";
    echo "                                                         888  88       88888       \n";
    echo "                                                          88888           888    \n";
    echo "                                                           888       0000000\n";
    echo "===================================================================================================================================\n";
    echo "                                                                  by RXCER\n";
    echo "===============================================\n";
    echo "                  Recon Tools\n";
    echo "===============================================\n";
    echo "1. Network Scanning Options\n";
    echo "2. Lookup Options\n";
    echo "3. Local Network Options\n";
    echo "4. Exit\n";
    echo "===============================================\n";
    
    $choice = readline("Enter your choice: ");

    switch ($choice) {
        case 1:
            scanMenu();
            break;
        case 2:
            lookupMenu();
            break;
        case 3:
            localMenu();
            break;
        case 4:
            exit("Exiting...\n");
            break;
        default:
            echo "Invalid choice, please try again.\n";
            mainMenu();
            break;
    }
}

// Function to display the scan menu
function scanMenu() {
    clearScreen();
    echo "===============================================\n";
    echo "          Network Scanning Options\n";
    echo "===============================================\n";
    echo "1. DNS Lookup + Cloudflare Detector\n";
    echo "2. Zone Transfer\n";
    echo "3. Port Scan\n";
    echo "4. HTTP Header Grabber\n";
    echo "5. Honeypot Detector\n";
    echo "6. Robots.txt Scanner\n";
    echo "7. Link Grabber\n";
    echo "8. Traceroute\n";
    echo "9. Grab Banners\n";
    echo "10. Subnet Calculator\n";
    echo "11. Sub-Domain Scanner\n";
    echo "12. Error Based SQLi Scanner\n";
    echo "13. Bloggers View\n";
    echo "14. Wordpress Scan\n";
    echo "15. Crawler\n";
    echo "16. MX Lookup\n";
    echo "17. Scan All\n";
    echo "18. Back to Main Menu\n";
    echo "===============================================\n";
    
    $choice = readline("Enter your choice: ");

    switch ($choice) {
        case 1:
            dnsLookup();
            break;
        case 2:
            zoneTransfer();
            break;
        case 3:
            portScan();
            break;
        case 4:
            httpHeader();
            break;
        case 5:
            honeypot();
            break;
        case 6:
            robotsTxt();
            break;
        case 7:
            linkGrabber();
            break;
        case 8:
            traceroute();
            break;
        case 9:
            grabBanners();
            break;
        case 10:
            subnetCalc();
            break;
        case 11:
            subDomainScanner();
            break;
        case 12:
            sqlScanner();
            break;
        case 13:
            bloggersView();
            break;
        case 14:
            wordpressScan();
            break;
        case 15:
            crawler();
            break;
        case 16:
            mxLookup();
            break;
        case 17:
            scanAll();
            break;
        case 18:
            mainMenu();
            break;
        default:
            echo "Invalid choice, please try again.\n";
            scanMenu();
            break;
    }
}

// Function to display the lookup menu
function lookupMenu() {
    clearScreen();
    echo "===============================================\n";
    echo "              Lookup Options\n";
    echo "===============================================\n";
    echo "1. WHOIS Lookup\n";
    echo "2. IP Location Finder\n";
    echo "3. Back to Main Menu\n";
    echo "===============================================\n";
    
    $choice = readline("Enter your choice: ");

    switch ($choice) {
        case 1:
            whoisLookup();
            break;
        case 2:
            ipLocator();
            break;
        case 3:
            mainMenu();
            break;
        default:
            echo "Invalid choice, please try again.\n";
            lookupMenu();
            break;
    }
}

// Function to display the local network menu
function localMenu() {
    clearScreen();
    echo "===============================================\n";
    echo "            Local Network Options\n";
    echo "===============================================\n";
    echo "1. Scan your local network\n";
    echo "2. Back to Main Menu\n";
    echo "===============================================\n";
    
    $choice = readline("Enter your choice: ");

    switch ($choice) {
        case 1:
            localScan();
            break;
        case 2:
            mainMenu();
            break;
        default:
            echo "Invalid choice, please try again.\n";
            localMenu();
            break;
    }
}

// Function to perform WHOIS lookup
function whoisLookup() {
    $target = readline("Enter the domain for WHOIS lookup: ");
    echo "Performing WHOIS lookup for $target...\n";
    $output = shell_exec("whois $target");
    echo $output;
    readline("Press Enter to continue...");
    lookupMenu();
}

// Function to perform DNS Lookup + Cloudflare Detector
function dnsLookup() {
    $target = readline("Enter the domain for DNS lookup: ");
    echo "Performing DNS lookup for $target...\n";
    $output = shell_exec("nslookup $target");
    echo $output;
    echo "Detecting Cloudflare...\n";
    $output = shell_exec("nslookup -type=txt $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Zone Transfer
function zoneTransfer() {
    $target = readline("Enter the domain for Zone Transfer: ");
    echo "Attempting Zone Transfer for $target...\n";
    $output = shell_exec("nslookup -type=any $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Port Scan
function portScan() {
    $target = readline("Enter the IP address for port scanning: ");
    echo "Performing port scan on $target...\n";
    $output = shell_exec("nmap $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to grab HTTP Headers
function httpHeader() {
    $target = readline("Enter the URL to grab HTTP headers: ");
    echo "Grabbing HTTP headers for $target...\n";
    $output = shell_exec("curl -I $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to detect Honeypots
function honeypot() {
    $target = readline("Enter the IP address to detect Honeypot: ");
    echo "Detecting Honeypot for $target...\n";
    $output = shell_exec("nmap -sV --script=http-enum $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to scan for robots.txt
function robotsTxt() {
    $target = readline("Enter the domain to scan for robots.txt: ");
    echo "Scanning for robots.txt on $target...\n";
    $output = shell_exec("curl $target/robots.txt");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to grab links
function linkGrabber() {
    $target = readline("Enter the URL to grab links from: ");
    echo "Grabbing links from $target...\n";
    $output = shell_exec("curl -s $target | grep 'href='");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Traceroute
function traceroute() {
    $target = readline("Enter the domain or IP for traceroute: ");
    echo "Performing traceroute to $target...\n";
    $output = shell_exec("traceroute $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to grab banners
function grabBanners() {
    $target = readline("Enter the IP address or domain to grab banners from: ");
    echo "Grabbing banners for $target...\n";
    $output = shell_exec("nmap -sV --script=banner $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Subnet Calculation
function subnetCalc() {
    $subnet = readline("Enter the subnet (e.g., 192.168.1.0/24): ");
    echo "Calculating subnet for $subnet...\n";
    $output = shell_exec("nmap -sP $subnet");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Sub-Domain Scan
function subDomainScanner() {
    $domain = readline("Enter the domain for sub-domain scan: ");
    echo "Scanning sub-domains for $domain...\n";
    $output = shell_exec("sublist3r -d $domain");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Error Based SQLi Scan
function sqlScanner() {
    $url = readline("Enter the URL for SQLi scan: ");
    echo "Scanning $url for SQLi...\n";
    $output = shell_exec("sqlmap -u $url --batch");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Bloggers View scan
function bloggersView() {
    $target = readline("Enter the URL to view blog details: ");
    echo "Viewing blog details for $target...\n";
    $output = shell_exec("curl -s $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Wordpress Scan
function wordpressScan() {
    $target = readline("Enter the URL to scan for Wordpress: ");
    echo "Scanning $target for Wordpress...\n";
    $output = shell_exec("wpscan --url $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Crawler scan
function crawler() {
    $target = readline("Enter the URL to crawl: ");
    echo "Crawling $target...\n";
    $output = shell_exec("wget --spider -r $target");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform MX Lookup
function mxLookup() {
    $domain = readline("Enter the domain for MX lookup: ");
    echo "Performing MX lookup for $domain...\n";
    $output = shell_exec("dig MX $domain");
    echo $output;
    readline("Press Enter to continue...");
    scanMenu();
}

// Function to perform Local Network Scan
function localScan() {
    echo "Scanning local network...\n";
    $output = shell_exec("nmap -sn 192.168.1.0/24");
    echo $output;
    readline("Press Enter to continue...");
    localMenu();
}

// Function to perform IP Location Finder
function ipLocator() {
    $ip = readline("Enter the IP address to find its location: ");
    echo "Finding location for $ip...\n";
    $output = shell_exec("curl ipinfo.io/$ip");
    echo $output;
    readline("Press Enter to continue...");
    lookupMenu();
}

// Start the script by showing the main menu
mainMenu();

?>
