FROM kalilinux/kali-rolling:latest

WORKDIR /scripts

WORKDIR /data 

RUN apt update

RUN apt upgrade -y

RUN apt dist-upgrade -y

RUN apt install wget -y

RUN apt install git -y

RUN apt install golang -y
# RUN wget https://go.dev/dl/go1.20.5.linux-amd64.tar.gz
# RUN rm -rf /usr/local/go && tar -C /usr/local -xzf go1.20.5.linux-amd64.tar.gz
# RUN export PATH=$PATH:/usr/local/go/bin

RUN apt install python3 -y

RUN apt install python3-pip -y

RUN pip3 install uuid

RUN go clean -modcache

RUN go env -w GO111MODULE=auto

#SUBDOMAIN TOOLS
# RUN apt install sublist3r -y

RUN go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
RUN mv /root/go/bin/subfinder /usr/bin/

RUN go install -v github.com/tomnomnom/assetfinder@latest
RUN mv /root/go/bin/assetfinder /usr/bin/

RUN go install -v github.com/owasp-amass/amass/v3/cmd/amass@latest
RUN mv /root/go/bin/amass /usr/bin

RUN go install -v github.com/projectdiscovery/chaos-client/cmd/chaos@latest
RUN mv /root/go/bin/chaos /usr/bin

#IP UTILS AND PORTSCAN TOOLS
RUN go install -v github.com/openrdap/rdap/cmd/rdap@master
RUN mv /root/go/bin/rdap /usr/bin/

# RUN apt install nmap -y

# WEB ENUMERATION TOOLS
RUN go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
RUN mv /root/go/bin/httpx /usr/bin/

RUN go install github.com/tomnomnom/waybackurls@latest
RUN mv /root/go/bin/waybackurls /usr/bin/

RUN go install github.com/projectdiscovery/katana/cmd/katana@latest
RUN mv /root/go/bin/katana /usr/bin

# RUN apt install gobuster -y

## VULN SCAN TOOLS
RUN go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
RUN mv /root/go/bin/nuclei /usr/bin/
RUN nuclei -up
RUN nuclei -ut

# RUN apt install nikto -y

## BRUTE FORCE TOOLS
# RUN apt install hydra -y

## OSINT TOOLS - in progress
# RUN apt install ripgrep -y