#!/usr/bin/env bash

# Wounty v1.1 (GNU/Linux x86_64).
# Copyright (C) 2021 egrullon <Amix>.
# License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl-3.0.html>.
# This program comes with ABSOLUTELY NO WARRANTY.
# This is free software and you are free to change and redistribute it.

# Author: egrullon <Amix>
# Date: 2021-09-10
# egrullon@cystrong.com
# www.cystrong.com
# Description: A simple web evaluation script to automate the early recognition stages in Bug Bounty processes.


# Bash Strict Mode
set -eo pipefail

# ANSI Colors
re="\e[0;91m"
wh="\e[0;97m"

target=$1


# Functions

banner() {
    echo " 

       █████   ███   █████                                 █████              
      ░░███   ░███  ░░███                                 ░░███               
       ░███   ░███   ░███   ██████  █████ ████ ████████   ███████   █████ ████
       ░███   ░███   ░███  ███░░███░░███ ░███ ░░███░░███ ░░░███░   ░░███ ░███ 
       ░░███  █████  ███  ░███ ░███ ░███ ░███  ░███ ░███   ░███     ░███ ░███ 
        ░░░█████░█████░   ░███ ░███ ░███ ░███  ░███ ░███   ░███ ███ ░███ ░███ 
          ░░███ ░░███     ░░██████  ░░████████ ████ █████  ░░█████  ░░███████ 
           ░░░   ░░░       ░░░░░░    ░░░░░░░░ ░░░░ ░░░░░    ░░░░░    ░░░░░███ 
                                                                     ███ ░███ 
                                                                    ░░██████  
                                                                     ░░░░░░  v1.1
         "

    return 0
}

function usage() {
    banner
    echo -e "\n${re}[${wh}*${re}] You need to put a valid Domain!! ${reset}"
    echo -e "${re}[${wh}*${re}] Usage: sudo bash wounty.sh cystrong.com\n  ${reset}"
}

function validate_url() {
    url_header=$(curl -s --head $target | head -n1 | grep -i "HTTP/[1-3].[0-9] [23]");
    return 0;
}

if [[ "$target" == '' ]]; then
    usage
else
    clear
    banner
    validate_url
    
    echo
    # Create directory infrastructure
    echo "[+] Creating infrastructure..."
    sleep 2

    mkdir -p $target/{info_gath,content,aquatone,scan/{masscan,nmap},exploits,scripts,tmp,fuzz}
    cd $target/info_gath
    
    echo
    echo "[+] Information gathering..."
    
    # Whatweb
    whatweb -v $target > whatweb_$target.txt
    
    # Wafw00f
    wafw00f $target > waf_$target.txt
    
    # SSLScan
    sslscan --no-check-certificate --no-renegotiation --no-heartbleed $target | grep -i preferred > sslscan_$target.txt &&
    
    echo
    echo "[+] Recognition..."
    cd ../content
    dig $target +short | awk 'NR == 1 { print $1 }' > ip_$target.txt &&
    cat ip_$target.txt | xargs whois -h whois.cymru.com | awk 'NR == 2 { print $1 }' > asn_$target.txt
        
    # Assetfinder
    assetfinder --subs-only $target | sort -u > sub_domains_$target.txt &&
    
    # Dig
    dig -f sub_domains_$target.txt A +short | sort -u | tr -d [:alpha:] | grep "\w" > sub_domains_ip_$target.txt &&
    dig +nocmd -f sub_domains_$target.txt cname +noall +answer | awk '{ print $5 }' | sort -u > sub_domains_reg_cname_$target.txt &&
    
    # Dnsgen and Httprobe
    echo -e "dev\nqa\nstage" > dnsgen.txt
    echo $target > $target.txt
    
    dnsgen -w dnsgen.txt $target.txt | httprobe -c 75 > sub_domains_dnsgen_$target.txt &&
    cat sub_domains_$target.txt | httprobe -c 75 > sub_domains_alive_$target.txt &&
    cat sub_domains_$target.txt | httprobe -s -p https:8000 -p https:8008 -p https:8080 -p https:8443 . -c 50 > sub_domains_special_ports_$target.txt &&
    
    # Waybackurls
    waybackurls $target | grep "\.js" | uniq | sort > js_files_$target.txt &&
    
    # Hakrawler
    hakrawler -url $target -depth 1 > js2_files_$target.txt &&
    
    # Parallel
    cat js_files_$target.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk > js3_files_$target.txt &&
    
    # Aquatone
    cd ../aquatone &&
    cp ../content/sub_domains_alive_$target.txt . &&
    cat sub_domains_alive_* | aquatone -chrome-path /usr/bin/chromium -threads 50 -silent | grep -v timeout &&
    echo
        
    # Masscan
    echo
    echo "[+] Scanning..."
    cd ../scan/masscan &&
    cp ../../content/sub_domains_ip_$target.txt . &&
    masscan -p 0-65535 --rate 1000000 --open-only -iL sub_domains_ip_$target.txt 2>/dev/null > masscan_open_ports_$target.txt &&
    
    # Nmap
    cd ../nmap &&
    nmap -p- --open -sC -sV -T4 -n -iL ../../content/sub_domains_ip_$target.txt 2>/dev/null > nmap_scan_open_ports_$target.txt &&
    nmap -sC -sV -p8000,8008,8080,8443 -iL ../../content/sub_domains_special_ports_$target.txt 2>/dev/null > nmap_scan_special_ports_$target.txt &&
    echo
    
    # FFUF
    echo "[+] Fuzzing..."
    cd ../../fuzz &&   
    ffuf -s -c -w /usr/share/seclists/Discovery/Web-Content/raft-large-words.txt -u https://$target/FUZZ -t 100 > ffuf_webcontent_$target.txt &&
  
    sleep 2
    echo "Done..."
    echo  
fi
