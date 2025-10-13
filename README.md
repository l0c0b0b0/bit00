# BIT00

BIT00 is a multi-threaded reconnaissance tool which performs automated enumeration of osint, subdomains, ports, emails and vulnerabilities. It is intended as a time-saving tool on penetration testing.

The tool is splited into different modules, like OSINT - NETSCAN. Future work will be implemented LDAP for internal enumeration.

The tool works by firstly performing reconnaissance face before testing each host, even for the OSINT. From those initial results of the reconnaissance, the tool will launch further enumeration scans of those services or targets using a number of different tools.

Everything in the tool is highly configurable. The author will not be held responsible for negative actions that result from the mis-use of this tool.

**Disclaimer: While BIT00 endeavors to perform as much identification and enumeration of services as possible, there is no guarantee that every service will be identified, or that every service will be fully enumerated.**

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

## Usage

BIT00 uses Python 3 specific functionality and does not support Python 2.

* OSINT MODULE

```
usage: bit00.py osint [-h] [-v] [-ct <number>] [-cs <number>] [--disable-sanity-checks] [-t TARGET_FILE] [-o OUTPUT_DIR] [--only-scans-dir] [targets ...]

Perform OSINT reconnaissance to a domain

positional arguments:
  targets               Resolvable Hostname, IP addresses or CIDR notation.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  -ct, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default: 5
  -cs, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default: 10
  --disable-sanity-checks
                        Disable sanity checks for large target ranges
  -t, --targets TARGET_FILE
                        Read targets from file
  -o, --output OUTPUT_DIR
                        The output directory for results. Default: osint
  --only-scans-dir      Only create the "scans" directory for results.
```

* NETSCAN MODULE

```
usage: bit00.py netscan [-h] [-v] [-ct <number>] [-cs <number>] [--disable-sanity-checks] [-t TARGET_FILE] [--only-portscan] [--profile PROFILE] [-o OUTPUT_DIR] [--only-scans-dir] [--nmap NMAP | --nmap-append NMAP_APPEND] [targets ...]

Network reconnaissance tool to port scan and automatically enumerate services on multiple targets.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.

options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  -ct, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default: 5
  -cs, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default: 10
  --disable-sanity-checks
                        Disable sanity checks for large target ranges
  -t, --targets TARGET_FILE
                        Read targets from a file.
  --only-portscan       Only scan open ports and ips, enumeration services will NOT run. Default: False
  --profile PROFILE     The port scanning profile the intensity of the scan there are 3 modes: default => TOP1000, full => 65535, redteam => TOP100. Default: default
  -o, --output OUTPUT_DIR
                        The output directory for results. Default: recon
  --only-scans-dir      Only create the "scans" directory for results. Other directories (e.g. logs, scan) will not be created. Default: false
  --nmap NMAP           Override the {nmap_extra} variable in scans. Default: -vv -Pn
  --nmap-append NMAP_APPEND
                        Append to the default {nmap_extra} variable in scans.
```

### Supporting Packages

Several commands used in BIT00 may need to be installed, deppending on your OS:

| OSINT TOOLS | NETSCAN TOOLS |
|----------|----------|
|   spiderfoot    |   seclist     |
|   dnsrecon      |   curl        |
|   fierce        |   dnsrecon    |
|   cloud_enum    |   gobuster    |
|   asn           |   feroxbuster |
|   metagoofil    |   kerberoast  |
|   dnsutils      |   cmseek      |
|                 |   masscan     |
|                 |   enum4linux  |
|                 |   gobuster    |
|                 |   impacket-scripts  |
|                 |   nbtscan           |
|                 |   nmap        |
|                 |   redis-tools |
|                 |     smbclient     |
|                 | smbmap      |
|                 | snmpwalk    |
|                 |   sslscan   |
|                 | svwar   |
|                 | whatweb |
|                 | nuclei  |
|                 | netexec |


On Kali Linux, you can ensure these are all installed using the following commands:

```bash
sudo apt install seclists curl dnsrecon enum4linux feroxbuster gobuster impacket-scripts nbtscan nmap redis-tools smbclient smbmap snmp sslscan sipvicious whatweb cmseek nuclei netexec spiderfoot dnsrecon fierce cloud_enum asn metagoofil dnsutils
```


### Verbosity

BIT00 supports four levels of verbosity:

* (none) Minimal output. BIT00 will announce when scanning targets starts / ends.
* (-v) Verbose output. BIT00 will additionally announce when plugins start running, and report found.
* (-vv) Very verbose output. BIT00 will additionally specify the exact commands which are being run by plugins, highlight any patterns which are matched in command output, and announce when plugins end.
* (-vvv) Very, very verbose output. BIT00 will output everything. Literally every line from all commands which are currently running. When scanning multiple targets concurrently, this can lead to a ridiculous amount of output. It is not advised to use -vvv unless you absolutely need to see live output from commands.

### Results

```

/osint
└── target.com
    ├── logs
    │   ├── _commands.log
    │   ├── _domainip.csv
    │   └── _patterns.log
    └── scans
        ├── info
        │   ├── cloud_cloudenum_target.com.csv
        │   ├── dataleak_metagoofil_target.com.txt
        │   ├── email_spiderfoot_target.com.ansi
        │   ├── geolocation_ipapi_10.10.10.10.json
        │   ├── geolocation_ipapi_10.10.10.11.json
        │   └── metadata_metagoogil.ansi
        ├── _manual_commands.txt
        ├── recon
        │   ├── cloud_cloudenum_target.com.ansi
        │   ├── cloud_spiderfoot_target.com.ansi
        │   ├── dns_dnsrecon_target.com.json
        │   ├── dns_fierce_target.com.ansi
        │   ├── dns_host_target.com.ansi
        │   ├── dns_sublist3r_target.com.txt
        │   ├── revdns_dig_target.com.ansi
        │   ├── revdns_dnsrecon_target.com.csv
        │   └── subdomains_sublist3r_target.com.txt
        └── tech
            ├── net_asn_10.10.10.10.json
            ├── net_asn_10.10.10.11.json
            ├── web_spiderfoot_target.com.ansi
            ├── web_spiderfoot_www.target.com.ansi
            ├── web_spiderfoot_capibara.target.com.ansi
            └── web_spiderfoot_plantillas-gobbo-drupal.demo.target.com.ansi


./recon
├── 10.10.10.10
│   ├── logs
│   │   ├── _commands.log
│   │   ├── _draft.log
│   │   └── _sumportsrv.log
│   └── scans
│       ├── gnmap
│       │   └── _top_1000_tcp_nmap.gnmap
│       ├── searchsploit-nmap-tcp.ansi
│       ├── _top_1000_tcp_nmap.txt
│       └── xml
│           └── _top_1000_tcp_nmap.xml
└── 10.10.10.11
    ├── logs
    │   ├── _commands.log
    │   ├── _draft.log
    │   └── _sumportsrv.log
    └── scans
        ├── gnmap
        │   └── _top_1000_tcp_nmap.gnmap
        ├── _manual_commands.txt
        ├── searchsploit-nmap-tcp.ansi
        ├── tcp_443_sslscan.txt
        ├── tcp_80_http_CMSeek.ansi
        ├── tcp_80_http_feroxbuster.txt
        ├── tcp_80_http_nmap.txt
        ├── tcp_80_http_nuclei.txt
        ├── tcp_80_http_robots.txt
        ├── tcp_80_http_whatweb.ansi
        ├── _top_1000_tcp_nmap.txt
        └── xml
            ├── tcp_80_http_nmap.xml
            └── _top_1000_tcp_nmap.xml


```

The logs directory is where all masscan/nmap scans data will save. This information is only for the port-scan-profiles.toml's commands:

* \_commands.log contains a list of every command BIT00 ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.

* If output matches a defined pattern, two files called \_sumportsrv.log and \_draft.log will also appear in the scans directory with details about the matched output.

* If a scan results in an error, a file called \_errors.log will also appear in the logs directory with some details to alert the user.

Scans directory:

* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.

> [!NOTE]
> BIT00 does NOT make any exploit o execute any PoC, its only reconnaissance!!!
