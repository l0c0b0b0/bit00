#!/bin/sh

# Bit00 Framework Installer
# Download first: curl -sL https://raw.githubusercontent.com/l0c0b0b0/bit00/main/install.sh -o install.sh
# Then run: sh install.sh

set -e

# Check if running in pipe mode (non-interactive)
if [ ! -t 0 ]; then
    echo "ERROR: This script requires interactive input."
    echo "Please download and run manually:"
    echo "  curl -sL https://raw.githubusercontent.com/l0c0b0b0/bit00/main/install.sh -o install.sh"
    echo "  sh install.sh"
    exit 1
fi

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

# Function to get user input with default
get_input() {
    prompt="$1"
    default="$2"
    
    while true; do
        echo "$prompt"
        printf "[%s]: " "$default"
        read response
        response=$(echo "$response" | tr '[:upper:]' '[:lower:]')
        if [ -n "$response" ]; then
            echo "$response"
            break
        elif [ -n "$default" ]; then
            echo "$default"
            break
        fi
    done
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
check_tool spiderfoot || true
check_tool dnsrecon || true
check_tool fierce || true
check_tool cloud-enum || true
check_tool asn || true 
check_tool theharvester || true
check_tool seclists || true
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

# Ask for installation confirmation
echo ""
echo "3. Install Packages and Tools:"
echo "This will install required packages and tools."
confirm_install=$(get_input "Do you want to proceed? (Y/n)" "y")

case "$confirm_install" in
    [nN]|[nN][oO])
        echo "Installation cancelled."
        exit 0
        ;;
    *)
        echo "[+] Start installing"
        echo "[+] Updating OS:"
        /usr/bin/sudo apt update
        
        echo "[+] Installing Main packages:"
        /usr/bin/sudo apt install -y git jq python3-colorama python3-tldextract golang curl
        
        echo "[+] Installing OSINT Tools:"
        /usr/bin/sudo apt install -y spiderfoot dnsrecon fierce cloud-enum asn theharvester
        
        echo "[+] Installing NETSCAN Tools:"
        /usr/bin/sudo apt install -y seclists dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec ffuf
        ;;
esac

# 4. Config Golang
echo ""
echo "4. Config Golang:"
echo "Default: GOPATH=/opt/go"
go_confirm=$(get_input "Use default Go paths? (Y/n)" "y")

case "$go_confirm" in
    [nN]|[nN][oO])
        go_path=$(get_input "Set Go directory path" "/opt/go")
        ;;
    *)
        go_path="/opt/go"
        ;;
esac

# Create Go directories
/usr/bin/sudo mkdir -p "$go_path"/bin "$go_path"/src "$go_path"/pkg
/usr/bin/sudo chown -R "$(id -u):$(id -g)" "$go_path"

# Detect shell and update profile
if [ -n "$ZSH_VERSION" ]; then
    shell_profile="$HOME/.zshrc"
else
    shell_profile="$HOME/.bashrc"
fi

# Add Go to shell profile
if ! grep -q "GOPATH=$go_path" "$shell_profile" 2>/dev/null; then
    {
        echo ""
        echo "# Go paths"
        echo "export GOPATH=$go_path"
        echo "export PATH=\$PATH:\$GOPATH/bin"
    } >> "$shell_profile"
    echo "[+] Added Go paths to $shell_profile"
fi

# Source the profile
. "$shell_profile"

export GOPATH="$go_path"
export PATH="$PATH:$GOPATH/bin"

# 5. Install Vulnx
echo ""
echo "5. Install Vulnx:"
vulnx_confirm=$(get_input "Install Vulnx? (Y/n)" "y")

case "$vulnx_confirm" in
    [nN]|[nN][oO])
        echo "Skipping Vulnx installation."
        ;;
    *)
        echo "[+] Installing Vulnx in dest: $GOPATH/bin/vulnx"
        /usr/bin/go install github.com/projectdiscovery/cvemap/cmd/vulnx@latest
        
        echo "[+] Changing name because there is a tool on github python called vulnx"
        /usr/bin/sudo ln -sf "$GOPATH/bin/vulnx" /usr/local/bin/vulnx00
        echo "Accessible from vulnx00 [Ok]"
        ;;
esac

# 6. Verify installation
echo ""
echo "6. Verification checklist:"
echo "Checking if main packages are installed:"
if command -v vulnx00 >/dev/null 2>&1; then
    echo "[+] vulnx00	 [Ok]"
else
    echo "[+] vulnx00	 [Not Found]"
fi

# 7. Install Bit00 framework
echo ""
echo "7. Installing Bit00 framework:"
bit00_dir="/opt/bit00"

if [ -d "$bit00_dir" ]; then
    echo "[+] Bit00 already exists at $bit00_dir"
    reinstall=$(get_input "Do you want to reinstall? (y/N)" "n")
    case "$reinstall" in
        [yY]|[yY][eE][sS])
            echo "[+] Removing existing installation"
            /usr/bin/sudo rm -rf "$bit00_dir"
            ;;
        *)
            echo "[+] Using existing installation"
            ;;
    esac
fi

if [ ! -d "$bit00_dir" ]; then
    echo "[+] Downloading from https://github.com/l0c0b0b0/Bit00.git"
    /usr/bin/sudo git clone https://github.com/l0c0b0b0/Bit00.git "$bit00_dir"
    
    echo "[+] Setting permissions to 755"
    /usr/bin/sudo chmod -R 755 "$bit00_dir"
fi

echo "[+] Creating symlink"
/usr/bin/sudo ln -sf "$bit00_dir/bit00.py" /usr/local/bin/bit00

# 8. Installation complete
echo ""
echo "8. Installation finish successfully!!!"
echo "Bit00 framework installed in: $bit00_dir"
echo "Accessible via: bit00"
echo ""
echo "Usage examples:"
echo "  bit00 --help"
echo "  bit00 -t example.com -m osint"
echo "  bit00 -t 192.168.1.0/24 -m netscan"
echo ""
echo "Please restart your terminal or run: source $shell_profile"