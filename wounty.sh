#!/usr/bin/env bash

# Wounty v1.3 (GNU/Linux x86_64).
# Copyright (C) 2021 egrullon <Amix>.
# License GPLv3+: GNU GPL version 3 or later <https://www.gnu.org/licenses/gpl-3.0.html>.
# This program comes with ABSOLUTELY NO WARRANTY.
# This is free software and you are free to change and redistribute it.

# Author: egrullon <Amix>
# Created: 2021-09-10
# Updated: 2022-02-05
# egrullon@cystrong.com
# www.cystrong.com
# Description: Wounty is a simple web enumeration script that makes use of other popular tools to automate the early stages of recognition in Bug Bounty processes.
#              This tool is very important as part of the Bug Bounties techniques.

# ANSI Colors
re="\e[0;91m"
wh="\e[0;97m"

target=$1

# Functions

banner() {
    echo -e " 
    
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
                                                                     ░░░░░░  ${re}v1.3${wh} ${reset}
    "     
    return 0
}

ctrl_c() {
    echo -e "${re} (Ctrl-C)${re}${wh}"
    sleep 1
}
trap ctrl_c INT

usage() {
    clear
    banner
    echo
    if [[ -n "$target" ]]; then
        echo -e "[${re}*${wh}] ${re}$target ${wh}is not a valid Domain!! ${reset}"
        echo -e "[${re}*${wh}] Usage: sudo wounty example.com ${reset}"
        sleep 1
    else
        echo -e "[${re}*${wh}] You need to put a valid Domain!! ${reset}"
        echo -e "[${re}*${wh}] Usage: sudo wounty example.com ${reset}"
        sleep 1
    fi
    return 0;
}

validate_fqdn() {
    host $target 2>&1 > /dev/null
        if [[ $? == 0 ]]; then
            echo
            echo -e "${re}Valid Target: ${re}${wh}${reset}"$target
        else
            usage
	    exit
        fi
        return 0;
}

if [[ "$target" == '' ]]; then
    usage
else
    clear
    banner
    validate_fqdn
    echo 
    
    # Create directory infrastructure
    echo -e "[${re}*${wh}] Creating infrastructure..."
    sleep 1
    mkdir -p $target/{info_gath,content,aquatone,scan/{masscan,nmap},yara,fuzz}
    cd $target/info_gath 
    
    # Information gathering 
    echo -e "[${re}*${wh}] Information gathering..."
    
    # Whatweb
    whatweb -v $target 2>/dev/null > whatweb_$target.txt
    
    # Wafw00f
    wafw00f $target 2>/dev/null > waf_$target.txt
    
    # SSLScan
    sslscan --no-check-certificate --no-renegotiation --no-heartbleed $target | grep -i preferred 2>/dev/null > sslscan_$target.txt
     
    # Recognition
    echo -e "[${re}*${wh}] Recognition..."
    cd ../content
    dig $target +short | awk 'NR == 1 { print $1 }' > ip_$target.txt

    if [[ -e "ip_$target.txt" ]]; then
        cat ip_$target.txt | xargs whois -h whois.cymru.com | awk 'NR == 2 { print $1 }' > asn_$target.txt
    else
	echo "The file ip_$target.txt was not create..."
    fi

    # Assetfinder
    assetfinder --subs-only $target | sort -u 2>/dev/null > sub_domains_$target.txt
        
    # Dig
    dig -f sub_domains_$target.txt A +short | sort -u | tr -d [:alpha:] | grep "\w" > sub_domains_ip_$target.txt
    dig +nocmd -f sub_domains_$target.txt cname +noall +answer | awk '{ print $5 }' | sort -u > sub_domains_reg_cname_$target.txt
    
    # Dnsgen and Httprobe
    echo -e "dev\ndevelopment\nlive\nstag\nstaging\nprod\nproduction\ntest\nqa\nstage" > dnsgen.txt
    echo $target > $target.txt
    
    if [[ -e "dnsgen.txt" ]]; then
        dnsgen -w dnsgen.txt $target.txt | httprobe -c 75 2>/dev/null > sub_domains_dnsgen_$target.txt 
        cat sub_domains_$target.txt | httprobe -c 75 2>/dev/null > sub_domains_alive_$target.txt 
        cat sub_domains_$target.txt | httprobe -s -p https:8000 -p https:8008 -p https:8080 -p https:8443 . -c 50 2>/dev/null > sub_domains_special_ports_$target.txt 
    else
	echo "The file dnsgen.txt was not create..."
    fi    

    # Waybackurls
    waybackurls $target | grep "\.js" | uniq | sort 2>/dev/null > js_files_$target.txt
    
    # Hakrawler
    cat sub_domains_alive_$target.txt | hakrawler 2>/dev/null > js2_files_$target.txt
    
    # Parallel
    cat js_files_$target.txt | parallel -j50 -q curl -w 'Status:%{http_code}\t Size:%{size_download}\t %{url_effective}\n' -o /dev/null -sk > js3_files_$target.txt
    
    # Aquatone
    cd ../aquatone
    cat ../content/sub_domains_alive_$target.txt | aquatone -chrome-path /usr/bin/chromium -threads 50 -silent | grep -v timeout 2>/dev/null

    # Masscan
    echo -e "[${re}*${wh}] Scanning..."
    cd ../scan/masscan 
        
    if [[ -e "../../content/sub_domains_ip_$target.txt" ]]; then
        masscan -p 0-65535 --rate 1000000 --open-only -iL ../../content/sub_domains_ip_$target.txt 2>/dev/null > masscan_open_ports_$target.txt
    else
        echo "MASSCAN failed - The file sub_domains_ip_$target.txt was not create..."
    fi
    
    # Nmap
    cd ../nmap 
    
    if [[ -e "../../content/sub_domains_ip_$target.txt" ]]; then
        nmap -sCV -p- --open --min-rate 5000 -n -iL ../../content/sub_domains_ip_$target.txt 2>/dev/null > nmap_scan_open_ports_$target.txt
    else
        echo "NMAP failed - The file sub_domains_ip_$target.txt was not create..."
    fi
    
    # FFUF
    echo -e "[${re}*${wh}] Fuzzing..."
    cd ../../fuzz
    curl -fsL https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-large-words.txt -o raft-large-words.txt
    ffuf -v -s -c -w raft-large-words.txt -u https://$target/FUZZ -t 100 2>/dev/null > ffuf_webcontent_$target.txt
    rm -f raft-large-words.txt

    # YARA Rules
    echo -e "[${re}*${wh}] Finding Strings with YARA Rules..."
    cd ../yara

cat << EOF > wounty_yara_rules.yar
rule WountyRule: wounty_yara {                  
    meta:                                      
        Author      = "egrullon <Amix>"
	Description = "Yara rule for detect posibles strings."		
        Date        = "2021-12-13"                   
                                                     
    strings:                                    
        $ = "pass"       nocase ascii          
        $ = "user"       nocase ascii          
        $ = "key"        nocase ascii          
        $ = "database"   nocase ascii          
        $ = "api"        nocase ascii          
        $ = "json"       nocase ascii          
        $ = "back"       nocase ascii          
        $ = "secret"     nocase ascii          
        $ = "exe" 	 nocase ascii
        $ = "access"     nocase ascii
        $ = "token"      nocase ascii
        $ = "admin"      nocase ascii
        $ = "aws"        nocase ascii          
        $ = "v1"         nocase ascii
        $ = "v2"         nocase ascii
        $ = "v3"         nocase ascii
        $ = "v4"         nocase ascii
        $ = "oauth"      nocase ascii
        $ = "dev"        nocase ascii
        $ = "url"        nocase ascii
        $ = "uri"        nocase ascii
                                                     
    condition:                                 
        (any of them)      
}
EOF
    
    yara wounty_yara_rules.yar -r ../../$target > yara_data_$target.txt
    rm -f wounty_yara_rules.yar
    echo    
    sleep 2
    echo -e "${re}All Done...${re}"
    echo -e "${re}Happy Hacking!!${reset}"
fi

