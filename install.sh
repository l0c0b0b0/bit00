#!/bin/bash

# Bit00 Framework Installer
# curl -sL https://github.com/l0c0b0b0/bit00/install.sh | sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Print banner
echo -e "${BLUE}"
cat << "EOF"
 ____    _   _      ___     ___  
| __ )  (_) | |_   / _ \   / _ \ 
|  _ \  | | | __| | | | | | | | |
| |_) | | | | |_  | |_| | | |_| |
|____/  |_|  \__|  \___/   \___/ 
EOF
echo -e "${NC}"
echo -e "${YELLOW}The network reconnaissance tool with multiple modules.${NC}"
echo -e "${YELLOW}Maintained as an open source project by @l0c0b0b0${NC}"
echo -e "${BLUE}Version : 1.0${NC}"
echo ""

# Function to check command existence
check_command() {
    if command -v "$1" &> /dev/null; then
        echo -e "[+] $1\t ${GREEN}[Ok]${NC}"
        return 0
    else
        echo -e "[+] $1\t ${RED}[Not Found]${NC}"
        return 1
    fi
}

# Function to install_go
install_go_custom() {
    echo -e "${YELLOW}[+] Setting up custom Go installation...${NC}"
    read -p "Set Go executable path (default: /usr/local/go): " go_root
    go_root=${go_root:-/usr/local/go}
    
    read -p "Set Go directory path (default: /opt/go): " go_path
    go_path=${go_path:-/opt/go}
    
    # Create directories
    sudo mkdir -p "$go_path"/{bin,src,pkg}
    
    # Detect shell and add to profile
    current_shell=$(basename "$SHELL")
    
    if [ "$current_shell" = "zsh" ]; then
        echo "export GOROOT=$go_root" >> ~/.zshrc
        echo "export GOPATH=$go_path" >> ~/.zshrc
        echo "export PATH=\$GOROOT/bin:\$GOPATH/bin:\$PATH" >> ~/.zshrc
        echo -e "${GREEN}[+] Added to ~/.zshrc${NC}"
        source ~/.zshrc
    else
        echo "export GOROOT=$go_root" >> ~/.bashrc
        echo "export GOPATH=$go_path" >> ~/.bashrc
        echo "export PATH=\$GOROOT/bin:\$GOPATH/bin:\$PATH" >> ~/.bashrc
        echo -e "${GREEN}[+] Added to ~/.bashrc${NC}"
        source ~/.bashrc
    fi
    
    export GOROOT=$go_root
    export GOPATH=$go_path
    export PATH=$GOROOT/bin:$GOPATH/bin:$PATH
}

# Step 2: Check main packages and tools
echo -e "${BLUE}[2] Checking main packages and tools:${NC}"
echo "List all Tools need by the framework and check if are installed:"

tools=("jq" "go" "git" "python3-colorama python3-tldextract" "curl" "seclists" "dnsrecon" "enum4linux" "feroxbuster" "gobuster" "impacket-scripts" "nbtscan" "nmap" "redis-tools" "smbclient" "smbmap" "snmp" "sslscan" "sipvicious" "whatweb" "cmseek" "nuclei" "netexec" "ffuf" "spiderfoot" "dnsrecon" "fierce" "cloud-enum" "asn" "dnsutils" "theharvester")
missing_tools=()

for tool in "${tools[@]}"; do
    if ! check_command "$tool"; then
        missing_tools+=("$tool")
    fi
done

read -p "Do you want to procced the installation? (Y/n): " use_default
# Step 3: Install Packages and Tools
echo ""
echo -e "${BLUE}[3] Install Packages and Tools:${NC}"
echo -e "${GREEN}[+] Start installing${NC}"

# Update OS
echo -e "${YELLOW}[+] Updating OS:${NC}"
sudo apt update

echo -e "${YELLOW}[+] Installing packages...:${NC}"

# Main packages
echo -e "${BLUE}[+] Installing main packages...${NC}"
sudo apt install git jq python3-colorama python3-tldextract curl -y

# OSINT Tools
echo -e "${BLUE}[+] Installing OSINT tools...${NC}"
#sudo apt install spiderfoot dnsrecon fierce cloud-enum asn dnsutils theharvester -y

# NETSCAN Tools
echo -e "${BLUE}[+] Installing NETSCAN tools...${NC}"
#sudo apt install seclists dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec ffuf -y

# Step 4: Configure Golang
echo ""
echo -e "${BLUE}[4] Config Golang:${NC}"

# Check if Go is installed
if ! command -v go &> /dev/null; then
    echo -e "${RED}[!] Go is not installed. Installing...${NC}"
    sudo apt install golang-go -y
fi

echo -e "${YELLOW}Default: GOROOT=/usr/local/go${NC}"
echo -e "${YELLOW}Default: GOPATH=/opt/go${NC}"

read -p "Use default Go paths? (Y/n): " use_default
case "$use_default" in
    [nN]|[nN][oO])
        install_go_custom
        ;;
    *)
        # Set default Go paths
        export GOROOT=/usr/local/go
        export GOPATH=/opt/go
        
        # Create default directory
        sudo mkdir -p /opt/go/{bin,src,pkg}
        sudo chown -R $USER:$USER /opt/go
        
        # Detect shell and add to profile
        current_shell=$(basename "$SHELL")
        
        if [ "$current_shell" = "zsh" ]; then
            echo "export GOPATH=/opt/go" >> ~/.zshrc
            echo "export PATH=\$GOPATH/bin:\$PATH" >> ~/.zshrc
            echo -e "${GREEN}[+] Added to ~/.zshrc${NC}"
            source ~/.zshrc
        else
            echo "export GOPATH=/opt/go" >> ~/.bashrc
            echo "export PATH=\$GOPATH/bin:\$PATH" >> ~/.bashrc
            echo -e "${GREEN}[+] Added to ~/.bashrc${NC}"
            source ~/.bashrc
        fi
        ;;
esac

# Step 5: Install Vulnx
echo ""
echo -e "${BLUE}[5] Installing Vulnx...${NC}"
echo -e "${GREEN}[+] Installing Vulnx in dest: /opt/go/bin/vulnx${NC}"

# Install vulnx
go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest

# Create symlink with different name
echo -e "${YELLOW}[+] Changing name because there is a tool on github python called vulnx${NC}"
sudo ln -sf /opt/go/bin/vulnx /usr/local/bin/vulnx00

# Verify installation
if command -v vulnx00 &> /dev/null; then
    echo -e "${GREEN}[+] Accessible from $(basename "$SHELL")/vulnx00 [Ok]${NC}"
else
    echo -e "${RED}[!] Failed to install vulnx00${NC}"
    exit 1
fi

# Step 6: Verify all installations
echo ""
echo -e "${BLUE}[6] Verification checklist:${NC}"

final_tools=("jq" "go" "git" "python3-colorama python3-tldextract" "curl" "seclists" "dnsrecon" "enum4linux" "feroxbuster" "gobuster" "impacket-scripts" "nbtscan" "nmap" "redis-tools" "smbclient" "smbmap" "snmp" "sslscan" "sipvicious" "whatweb" "cmseek" "nuclei" "netexec" "ffuf" "spiderfoot" "dnsrecon" "fierce" "cloud-enum" "asn" "dnsutils" "theharvester")
all_ok=true

for tool in "${final_tools[@]}"; do
    if command -v "$tool" &> /dev/null; then
        echo -e "[+] $tool\t ${GREEN}[Ok]${NC}"
    else
        echo -e "[+] $tool\t ${RED}[Not Found]${NC}"
        all_ok=false
    fi
done

if [ "$all_ok" = false ]; then
    echo -e "${RED}[!] Some tools failed to install. Please check manually.${NC}"
    exit 1
fi

# Step 7: Download and install Bit00
echo ""
echo -e "${BLUE}[7] Downloading and installing Bit00 framework...${NC}"

bit00_dir="/opt/bit00"

# Clone repository
sudo git clone https://github.com/l0c0b0b0/Bit00.git "$bit00_dir"

# Set permissions
sudo chmod -R 755 "$bit00_dir"

# Create symlink
sudo ln -sf "$bit00_dir/bit00.py" /usr/local/bin/bit00

# Make main script executable
sudo chmod +x "$bit00_dir/bit00.py"

# Step 8: Installation complete
echo ""
echo -e "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════╗
║        Installation Complete!         ║
╚═══════════════════════════════════════╝
EOF
echo -e "${NC}"

echo -e "${GREEN}[+] Bit00 framework installed successfully!${NC}"
echo -e "${GREEN}[+] Location: $bit00_dir${NC}"
echo -e "${GREEN}[+] Accessible via: bit00${NC}"
echo ""
echo -e "${YELLOW}Usage:${NC}"
echo -e "  bit00 --help"
echo -e "  bit00 -t example.com -m osint"
echo ""
echo -e "${BLUE}Thank you for installing Bit00!${NC}"