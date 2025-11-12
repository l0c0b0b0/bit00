# 🔍 BIT00 - Automated Reconnaissance Tool

BIT00 automates OSINT gathering and network scanning to save time on security assessments.

> **⚠️ Legal Notice**: Only use on systems you own or have explicit permission to test.

## 🚀 Quick Start

### Prerequisites

- Linux (Kali, Ubuntu, Debian recommended)
- Python 3.8 or higher
- Root/sudo access for tool installation

### Installation

1. **Update your system, install Python required packages:**

    ```bash
    sudo apt update && sudo chmod +x install.sh
    ```

2. **Install:**

    ```bash
    sudo ./install.sh
    ```

## 📖 Basic Usage

Gather intelligence about domains and organizations.

**OSINT Basic usage:**

```bash
sudo bit00 osint example.com
sudo bit00 osint company.com -v -ct 3
```

**NetScan Basic usage:**

```bash
sudo bit00 netscan 192.168.1.0/24
sudo bit00 netscan 10.10.10.5 -p full -v
```

## 🛠️ Required Tools

### OSINT Tools

```bash
sudo apt install spiderfoot dnsrecon fierce cloud_enum asn metagoofil dnsutils theharvester
```

### NETSCAN Tools

```bash
sudo sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec ffuf
```

## 📊 Output

Results are saved in multiple formats:

- results.json - Machine readable
- results.txt - Human readable
- results.xml - Standard format

```text
~$ 
├── osint/
│   └── example.com/
│       ├── logs/
│       │   ├── commands.log    # All commands executed
│       │   ├── error.log       # Error messages
│       │   └── patterns.log    # Pattern matches
│       └── scans/              # Scan results
├── recon/
│   └── 10.10.10.5/
│        ├── logs/
│        │   ├── commands.log    # All commands executed
│        │   ├── error.log       # Error messages
│        │   └── patterns.log    # Pattern matches
│        └── scans/              # Scan results
└──results/
    ├── results.json          # Structured data (JSON)
    ├── results.txt           # Human-readable report
    └── results.xml           # Machine-readable report
```

## 🔧 Verbosity Levels

- (no flag): Basic progress updates
- -v: Plugin starts and important findings
- -vv: Commands being executed and pattern matches
- -vvv: Full debug output (use sparingly)

## 🆘 Help

```bash
python bit00.py --help
python bit00.py osint --help
python bit00.py netscan -L  # List plugins
```

> [!NOTE]
> BIT00 performs reconnaissance only, **NO** exploitation or attacks.
