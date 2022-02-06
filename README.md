# Wounty

## Version:
Wounty v1.3 (GNU/Linux x86_64).

## License:
Copyright (C) 2021 egrullon \<Amix\>.

License GPLv3+: GNU GPL version 3 or later https://www.gnu.org/licenses/gpl-3.0.html.

This program comes with ABSOLUTELY NO WARRANTY.

This is free software and you are free to change and redistribute it.

## Description:

Wounty is a simple web enumeration script that makes use of other popular tools to automate the early stages of recognition in Bug Bounty processes. This tool is very important as part of the Bug Bounties techniques.

## Additional Tools:
### You need to install
- whatweb
- wafw00f
- sslscan
- assetfinder
- dnsgen
- httprobe
- waybackurls
- hakrawler
- parallel
- aquatone
- masscan
- nmap
- ffuf
- yara

## Normal Install:
```
cd /opt
```

### You can install cloning this Git Repository.
```
sudo git clone https://github.com/egrullon/Wounty.git
```
```
sudo chmod +x Wounty/wounty.sh
```

## Configuration:
```
sudo ln -s /opt/Wounty/wounty.sh /usr/local/bin/wounty
```

## Usage:
```
sudo wounty example.com
```

## Docker Install (from dockerhub)

```
docker pull egrullon/wounty:v2
```
```
docker run -it -v /tmp/:/opt/projects egrullon/wounty:v2
```

## Docker Install (local)
```
cd /opt
```
```
sudo git clone https://github.com/egrullon/WountyContainer.git
```
```
cd WountyContainer
```
```
docker build -t wounty:v2 .
```
```
docker run -it -v /tmp/:/opt/projects wounty:v2
```
### Usage:
```
wounty example.com
```

