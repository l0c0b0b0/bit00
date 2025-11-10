#!/bin/sh

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
echo "${BLUE}"
cat << "EOF"
 ____    _   _      ___     ___  
| __ )  (_) | |_   / _ \   / _ \ 
|  _ \  | | | __| | | | | | | | |
| |_) | | | | |_  | |_| | | |_| |
|____/  |_|  \__|  \___/   \___/ 
EOF
echo "${NC}"
echo "${YELLOW}The network reconnaissance tool with multiple modules.${NC}"
echo "${YELLOW}Maintained as an open source project by @l0c0b0b0${NC}"
echo "${BLUE}Version : 1.0${NC}"
echo ""

# Function to check command existence
check_command() {
    if command -v "$1" >/dev/null 2>&1; then
        echo "[+] $1\t ${GREEN}[Ok]${NC}"
        return 0
    else
        echo "[+] $1\t ${RED}[Not Found]${NC}"
        return 1
    fi
}

# Function to get user input
get_input() {
    prompt="$1"
    default="$2"
    echo -n "$prompt "
    if [ -n "$default" ]; then
        echo -n "[$default] "
    fi
    read response
    echo "${response:-$default}"
}

# Function to install_go
install_go_custom() {
    echo "${YELLOW}[+] Setting up custom Go installation...${NC}"
    go_root=$(get_input "Set Go executable path:" "/usr/local/go")
    go_path=$(get_input "Set Go directory path:" "/opt/go")
    
    # Create directories
    sudo mkdir -p "$go_path"/bin "$go_path"/src "$go_path"/pkg
    
    # Detect shell and add to profile
    if [ -n "$ZSH_VERSION" ]; then
        shell_profile="$HOME/.zshrc"
    else
        shell_profile="$HOME/.bashrc"
    fi
    
    {
        echo "export GOROOT=$go_root"
        echo "export GOPATH=$go_path" 
        echo "export PATH=\$GOROOT/bin:\$GOPATH/bin:\$PATH"
    } >> "$shell_profile"
    
    echo "${GREEN}[+] Added to $shell_profile${NC}"
    
    # Source the profile
    . "$shell_profile"
    
    export GOROOT="$go_root"
    export GOPATH="$go_path"
    export PATH="$GOROOT/bin:$GOPATH/bin:$PATH"
}

# Step 2: Check main packages and tools
echo "${BLUE}[2] Checking main packages and tools:${NC}"
echo "List all Tools need by the framework and check if are installed:"

tools="jq nmap curl go vulnx"
missing_tools=""

for tool in $tools; do
    if ! check_command "$tool"; then
        missing_tools="$missing_tools $tool"
    fi
done

# Ask for confirmation before installation
echo ""
echo "${YELLOW}=================================================${NC}"
echo "${YELLOW}           INSTALLATION CONFIRMATION            ${NC}"
echo "${YELLOW}=================================================${NC}"
echo ""
echo "The following packages will be installed:"
echo "  ${BLUE}• Main packages:${NC} git, jq, python3-colorama, python3-tldextract, golang, curl"
echo "  ${BLUE}• OSINT tools:${NC} spiderfoot, dnsrecon, fierce, cloud-enum, asn, dnsutils, theharvester"
echo "  ${BLUE}• NETSCAN tools:${NC} seclists, enum4linux, feroxbuster, gobuster, impacket-scripts, nbtscan, nmap, redis-tools, smbclient, smbmap, snmp, sslscan, sipvicious, whatweb, cmseek, nuclei, netexec, ffuf"
echo "  ${BLUE}• Go tools:${NC} vulnx (as vulnx00)"
echo "  ${BLUE}• Framework:${NC} Bit00 from GitHub"
echo ""
echo "${YELLOW}This will require sudo privileges and may take several minutes.${NC}"
echo ""

# Get user confirmation - using simple read
echo "Do you want to proceed with the installation? (y/N)"
echo -n "Enter your choice [y/N]: "
read user_confirm

# Convert to lowercase for comparison
user_confirm=$(echo "$user_confirm" | tr '[:upper:]' '[:lower:]')

case "$user_confirm" in
    y|yes)
        echo "${GREEN}[+] Proceeding with installation...${NC}"
        ;;
    *)
        echo "${RED}[!] Installation cancelled by user.${NC}"
        exit 0
        ;;
esac

# Step 3: Install Packages and Tools
echo ""
echo "${BLUE}[3] Install Packages and Tools:${NC}"
echo "${GREEN}[+] Start installing${NC}"

# Update OS
echo "${YELLOW}[+] Updating OS:${NC}"
sudo apt update

echo "${YELLOW}[+] Installing packages...:${NC}"

# Main packages
echo "${BLUE}[+] Installing main packages...${NC}"
sudo apt install -y git jq python3-colorama python3-tldextract golang curl

# OSINT Tools
echo "${BLUE}[+] Installing OSINT tools...${NC}"
sudo apt install -y spiderfoot dnsrecon fierce cloud-enum asn dnsutils theharvester

# NETSCAN Tools
echo "${BLUE}[+] Installing NETSCAN tools...${NC}"
sudo apt install -y seclists dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec ffuf

# Step 4: Configure Golang
echo ""
echo "${BLUE}[4] Config Golang:${NC}"

# Check if Go is installed
if ! command -v go >/dev/null 2>&1; then
    echo "${RED}[!] Go is not installed. Installing...${NC}"
    sudo apt install -y golang-go
fi

echo "${YELLOW}Default: GOROOT=/usr/local/go${NC}"
echo "${YELLOW}Default: GOPATH=/opt/go${NC}"

echo "Use default Go paths? (Y/n)"
echo -n "Enter your choice [Y/n]: "
read use_default

use_default=$(echo "$use_default" | tr '[:upper:]' '[:lower:]')

case "$use_default" in
    n|no)
        install_go_custom
        ;;
    *)
        # Set default Go paths
        export GOROOT=/usr/local/go
        export GOPATH=/opt/go
        
        # Create default directory
        sudo mkdir -p /opt/go/bin /opt/go/src /opt/go/pkg
        sudo chown -R "$(whoami):$(whoami)" /opt/go
        
        # Detect shell and add to profile
        if [ -n "$ZSH_VERSION" ]; then
            shell_profile="$HOME/.zshrc"
        else
            shell_profile="$HOME/.bashrc"
        fi
        
        {
            echo "export GOPATH=/opt/go"
            echo "export PATH=\$GOPATH/bin:\$PATH"
        } >> "$shell_profile"
        
        echo "${GREEN}[+] Added to $shell_profile${NC}"
        . "$shell_profile"
        ;;
esac

# Step 5: Install Vulnx
echo ""
echo "${BLUE}[5] Installing Vulnx...${NC}"
echo "${GREEN}[+] Installing Vulnx in dest: /opt/go/bin/vulnx${NC}"

# Install vulnx
"$GOROOT/bin/go" install github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest

# Create symlink with different name
echo "${YELLOW}[+] Changing name because there is a tool on github python called vulnx${NC}"
sudo ln -sf /opt/go/bin/nuclei /usr/local/bin/vulnx00

# Verify installation
if command -v vulnx00 >/dev/null 2>&1; then
    echo "${GREEN}[+] Accessible as vulnx00 [Ok]${NC}"
else
    echo "${RED}[!] Failed to install vulnx00${NC}"
    exit 1
fi

# Step 6: Verify all installations
echo ""
echo "${BLUE}[6] Verification checklist:${NC}"

final_tools="jq nmap curl go vulnx00 git python3 dnsrecon theharvester feroxbuster nuclei"
all_ok=true

for tool in $final_tools; do
    if command -v "$tool" >/dev/null 2>&1; then
        echo "[+] $tool\t ${GREEN}[Ok]${NC}"
    else
        echo "[+] $tool\t ${RED}[Not Found]${NC}"
        all_ok=false
    fi
done

if [ "$all_ok" = false ]; then
    echo "${RED}[!] Some tools failed to install. Please check manually.${NC}"
    exit 1
fi

# Step 7: Download and install Bit00
echo ""
echo "${BLUE}[7] Downloading and installing Bit00 framework...${NC}"

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
echo "${GREEN}"
cat << "EOF"
╔═══════════════════════════════════════╗
║        Installation Complete!         ║
╚═══════════════════════════════════════╝
EOF
echo "${NC}"

echo "${GREEN}[+] Bit00 framework installed successfully!${NC}"
echo "${GREEN}[+] Location: $bit00_dir${NC}"
echo "${GREEN}[+] Accessible via: bit00${NC}"
echo ""
echo "${YELLOW}Usage:${NC}"
echo "  bit00 --help"
echo "  bit00 -t example.com -m osint"
echo ""
echo "${BLUE}Thank you for installing Bit00!${NC}"