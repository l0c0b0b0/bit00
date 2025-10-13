# AutoRecon

AutoRecon is a multi-threaded reconnaissance tool which performs automated enumeration of subdomains, ports, emails and vulnerabilities. It is intended as a time-saving tool on penetration testing.

The tool works by firstly performing port scans /service detection scans. From those initial results, the tool will launch further enumeration scans of those services using a number of different tools.

Everything in the tool is highly configurable. The author will not be held responsible for negative actions that result from the mis-use of this tool.

**Disclaimer: While Autorecon endeavors to perform as much identification and enumeration of services as possible, there is no guarantee that every service will be identified, or that every service will be fully enumerated.**

## Origin

l0c0b0b0_!0X#$%>

## Installation

AutoRecon is a manually installation. Before installation using any of these methods, certain requirements need to be fulfilled. If you have not refreshed your apt cache recently, run the following command so you are installing the latest available packages:


```bash
sudo apt update
```

### Python3 

AutoRecon requires the usage of Python3.8+ and pip, which can be installed on Kali Linux using the following commands:

```bash
sudo apt install python3
sudo apt install python3-pip
sudo apt install python3-venv
```

### Supporting Packages

Several commands used in AutoRecon may need to be installed, deppending on your OS: 

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
* nuclei
* netexec



On Kali Linux, you can ensure these are all installed using the following commands:

```bash
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec
```

### Installation Method: Manually
Install and execute `autorecon.py` from within the RECON directory, install the dependencies:

```bash
(root) pip install -r requirements.txt
```

You can also create a VirtualEnviroment with python3:

```bash
(root) python3 -m venv .autorecon
(root) source .autorecon/bin/activate
(root) pip install -r requirements.txt
```
To exit the virtual enviromment:

```bash
(root) (autorecon) deactivate
```

You will then be able to run the `autorecon.py` script:

```bash
(root) python3 autorecon.py iptarget [options]
```

## Usage

AutoRecon uses Python 3 specific functionality and does not support Python 2.

```
usage: autorecon.py [-h] [-t TARGET_FILE] [-ct <number>] [-cs <number>] [--profile PROFILE_NAME] [-o OUTPUT_DIR] [--single-target] [--only-scans-dir] [--nmap NMAP | --nmap-append NMAP_APPEND] [-v] [--disable-sanity-checks]
                    [targets ...]

Network reconnaissance tool to port scan and automatically enumerate services found on multiple targets.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.

options:
  -h, --help            show this help message and exit
  -t, --targets TARGET_FILE
                        Read targets from file.
  -ct, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default: 5
  -cs, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default: 10
  --profile PROFILE_NAME
                        The port scanning profile to use (defined in port-scan-profiles.toml). Default: default
  -o, --output OUTPUT_DIR
                        The output directory for results. Default: recon
  --single-target       Only scan a single target. A directory named after the target will not be created. Instead, the directory structure will be created within the output directory. Default: false
  --only-scans-dir      Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false
  --nmap NMAP           Override the {nmap_extra} variable in scans. Default: -vv -Pn
  --nmap-append NMAP_APPEND
                        Append to the default {nmap_extra} variable in scans.
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --disable-sanity-checks
                        Disable sanity checks that would otherwise prevent the scans from running. Default: false
```

### Verbosity

AutoRecon supports four levels of verbosity:

* (none) Minimal output. AutoRecon will announce when scanning targets starts / ends.
* (-v) Verbose output. AutoRecon will additionally announce when plugins start running, and report found.
* (-vv) Very verbose output. AutoRecon will additionally specify the exact commands which are being run by plugins, highlight any patterns which are matched in command output, and announce when plugins end.
* (-vvv) Very, very verbose output. AutoRecon will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vvv unless you absolutely need to see live output from commands.

### Results

By default, results will be stored in the ./recon directory. A new sub directory is created for every target. The structure of this sub directory is:

```
./recon
├── targetip
│   ├── logs
│   │   ├── _commands.log
│   │   ├── _draft.log
│   │   ├── _sumportsrv.log
│   │   └── _vulns.log
│   └── scans
│       ├── gnmap
│       │   └── _top_1000_tcp_nmap.gnmap
│       ├── _manual_commands.txt
│       ├── searchsploit-nmap-tcp.ansi
│       ├── tcp_80_http_CMSeek.ansi
│       ├── tcp_80_http_feroxbuster.txt
│       ├── tcp_80_http_nmap.txt
│       ├── tcp_80_http_nuclei.txt
│       ├── tcp_80_http_robots.txt
│       ├── tcp_80_http_whatweb.ansi
│       ├── tcp_445_smb_netexec.ansi
│       ├── _top_1000_tcp_masscan.txt
│       ├── _top_1000_tcp_nmap.txt
│       └── xml                                                                                                                
│           ├── tcp_80_http_nmap.xml
│           └── _top_1000_tcp_nmap.xml
└── results                                                                                                                    
    ├── result.csv                                                                                                             
    ├── result.txt                                                                                                             
    └── vulns.csv
```

The logs directory is where all masscan/nmap scans data will save. This information is only for the port-scan-profiles.toml's commands:
* \_commands.log contains a list of every command AutoRecon ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.
* If output matches a defined pattern, two files called \_sumportsrv.log and \_draft.log will also appear in the scans directory with details about the matched output.
* If a scan results in an error, a file called \_errors.log will also appear in the logs directory with some details to alert the user.

Scans directory:
* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.