#!/bin/sh

# Bit00 Framework Installer
# curl -sL https://raw.githubusercontent.com/l0c0b0b0/bit00/main/install.sh | sh


set -e

# 1. Incoming message
cat << "EOF"
 ____    _   _      ___     ___  
| __ )  (_) | |_   / _ \   / _ \ 
|  _ \  | | | __| | | | | | | | |
| |_) | | | | |_  | |_| | | |_| |
|____/  |_|  \__|  \___/   \___/ 
EOF
echo "The network reconnaissance tool with multiple modules."
echo "Maintained as an open source project by @l0c0b0b0"
echo "Version : 1.0"
echo ""

# Function to check command
check_tool() {
    if /usr/bin/dpkg -s "$1" 2>/dev/null | grep -q "Status: install ok installed"; then
        printf "[+] %-12s [Ok]\n" "$1"
        return 0
    else
        printf "[+] %-12s [Not Found]\n" "$1"
        return 1
    fi
}


# 2. Checking main packages and tools
echo "2. Checking main packages and tools:"
echo "List all Tools need by the framework and check if are installed:"
check_tool git || true
check_tool jq || true
check_tool python3-colorama || true
check_tool python3-tldextract || true
check_tool golang || true
check_tool curl || true
check_tool dnsrecon || true
check_tool fierce || true
check_tool asn || true 
check_tool theharvester || true
check_tool seclists || true
check_tool dnsrecon || true
check_tool enum4linux || true
check_tool feroxbuster || true
check_tool gobuster || true
check_tool impacket-scripts || true
check_tool nbtscan || true
check_tool nmap || true
check_tool redis-tools || true
check_tool smbclient || true
check_tool smbmap || true
check_tool snmp || true
check_tool sslscan || true
check_tool sipvicious || true
check_tool whatweb || true
check_tool cmseek || true
check_tool nuclei || true
check_tool netexec || true
check_tool ffuf || true
check_tool sublist3r || true
check_tool naabu || true

# 3. Installation
echo ""
echo "3. Install Packages and Tools:"
echo "This will install required packages and tools."

echo "[+] Start installing"
echo "[+] Updating OS:"
/usr/bin/sudo apt update
        
echo "[+] Installing Main packages:"
/usr/bin/sudo apt install -y git jq python3-colorama python3-tldextract golang curl
        
echo "[+] Installing OSINT Tools:"
/usr/bin/sudo apt install -y dnsrecon fierce asn theharvester subfinder sublist3r
        
echo "[+] Installing NETSCAN Tools:"
/usr/bin/sudo apt install -y seclists dnsrecon naabu enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec ffuf


# Update nuclei an another tools
echo ""
echo "Update nuclei templates:"
/usr/bin/sudo apt install --only-upgrade nuclei
/usr/bin/sudo /usr/bin/nuclei -update-templates

echo "Upgrade tools:"
echo ""
/usr/bin/sudo apt install --only-upgrade seclists impacket-scripts nmap cmseek netexec

# 4. Install Vulnx

echo ""
echo "4. Install Vulnx:"

echo "[+] Installing Vulnx in dest: $GOPATH/bin/vulnx"
/usr/bin/go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
        
echo "[+] Changing name because there is a tool on github python called vulnx"
/usr/bin/sudo ln -sf "$GOPATH/bin/vulnx" /usr/local/bin/vulnx00
echo "Accessible from vulnx00 [Ok]"

# 5. Install Bit00 framework

echo ""
echo "5. Installing Bit00 framework:"

bit00_dir="/opt/bit00"

echo "[+] Downloading from https://github.com/l0c0b0b0/Bit00.git"
/usr/bin/sudo git clone https://github.com/l0c0b0b0/Bit00.git "$bit00_dir"

echo "[+] Setting permissions to 755"
/usr/bin/sudo chmod -R 755 "$bit00_dir"

echo "[+] Creating symlink"
/usr/bin/sudo ln -sf "$bit00_dir/bit00.py" /usr/local/bin/bit00

# 6. Installation complete

echo ""
echo "6. Installation finish successfully!!!"
echo "Bit00 framework installed in: $bit00_dir"
echo "Accessible via: bit00"
echo ""
echo "Usage examples:"
echo "  bit00 --help"
echo "  bit00 -t example.com -m osint"
echo "  bit00 -t 192.168.1.0/24 -m netscan"
