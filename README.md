# BIT00

BIT00 is a multi-threaded reconnaissance tool which performs automated enumeration of osint, subdomains, ports, emails and vulnerabilities. It is intended as a time-saving tool on penetration testing.

The tool is splited into different modules, like OSINT - NETSCAN. Future work will be implemented LDAP for internal enumeration.

The tool works by firstly performing reconnaissance face before testing each host, even for the OSINT. From those initial results of the reconnaissance, the tool will launch further enumeration scans of those services or targets using a number of different tools.

Everything in the tool is highly configurable. The author will not be held responsible for negative actions that result from the mis-use of this tool.

**Disclaimer: While BIT00 endeavors to perform as much identification and enumeration of services as possible, there is no guarantee that every service will be identified, or that every service will be fully enumerated.**

## Origin

l0c0b0b0_!0X#$%>

## Installation

BIT00 is a manually installation. Before installation using any of these methods, certain requirements need to be fulfilled. If you have not refreshed your apt cache recently, run the following command so you are installing the latest available packages:


```bash
sudo apt update
```

### Python3 

BIT00 requires the usage of Python3.8+ and pip, which can be installed on Kali Linux using the following commands:

```bash
sudo apt install python3
sudo apt install python3-pip
sudo apt install python3-venv
```

### Supporting Packages

Several commands used in BIT00 may need to be installed, deppending on your OS: 

* seclist
* curl
* dnsrecon
* gobuster
* feroxbuster
* kerberoast
* cmseek
* masscan
* enum4linux
* gobuster
* impacket-scripts
* nbtscan
* nmap
* redis-tools
* smbclient
* smbmap
* snmpwalk
* sslscan
* svwar
* whatweb
* spiderfoot
* dnsrecon
* fierce
* cloud_enum
* asn
* metagoofil
* dnsutils
* nuclei
* netexec


On Kali Linux, you can ensure these are all installed using the following commands:

```bash
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec spiderfoot dnsrecon fierce cloud_enum asn metagoofil dnsutils
```

### Installation Method: Manually
Install and execute `bit00.py` from within the RECON directory, install the dependencies:

```bash
(root) pip install -r requirements.txt
```

You can also create a VirtualEnviroment with python3 if you don't want to install on your OS the packages:

```bash
(root) python3 -m venv .bit00
(root) source .bit00/bin/activate
(root) pip install -r requirements.txt
```
To exit the virtual enviromment:

```bash
(root) (bit00) deactivate
```

You will then be able to run the `bit00.py` script:

```bash
(root) python3 bit00.py osint [options]
(root) python3 bit00.py netscan [options]
```

## Usage

BIT00 uses Python 3 specific functionality and does not support Python 2.

```

```

### Verbosity

BIT00 supports four levels of verbosity:

* (none) Minimal output. BIT00 will announce when scanning targets starts / ends.
* (-v) Verbose output. BIT00 will additionally announce when plugins start running, and report found.
* (-vv) Very verbose output. BIT00 will additionally specify the exact commands which are being run by plugins, highlight any patterns which are matched in command output, and announce when plugins end.
* (-vvv) Very, very verbose output. BIT00 will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vvv unless you absolutely need to see live output from commands.

### Results


```

```

The logs directory is where all masscan/nmap scans data will save. This information is only for the port-scan-profiles.toml's commands:
* \_commands.log contains a list of every command BIT00 ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.
* If output matches a defined pattern, two files called \_sumportsrv.log and \_draft.log will also appear in the scans directory with details about the matched output.
* If a scan results in an error, a file called \_errors.log will also appear in the logs directory with some details to alert the user.

Scans directory:
* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.