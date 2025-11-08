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
usage: bit00.py osint [-h] [-ct <number>] [-cs <number>] [-V] [-o OUTPUTDIR] [-oor] [-L] [-P PLUGIN] [-v] [--only-scans-dir] [targets ...]

Perform OSINT reconnaissance to a domain

positional arguments:
  targets               Resolvable Hostname, IP addresses or CIDR notation.

options:
  -h, --help            show this help message and exit
  -ct, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default: 5
  -cs, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default: 10
  -V, --version         Display version information and exit
  -o, --output OUTPUTDIR
                        The output directory for results. Default: osint
  -oor, --only-osint-recon
                        Only reconnaissance phase the "scans" tools will NOT be running.
  -L, --list-plugins    List all available OSINT plugins
  -P, --plugin PLUGIN   Run specific plugin instead of full scan
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  --only-scans-dir      Only create the "scans" directory for results.

```

* NETSCAN MODULE

```
usage: bit00.py netscan [-h] [-ct <number>] [-cs <number>] [-V] [-ops] [-p PROFILE] [-L] [-P PLUGIN] [-v] [-o OUTPUTDIR] [--only-scans-dir] [targets ...]

Network reconnaissance tool to port scan and automatically enumerate services on multiple targets.

positional arguments:
  targets               IP addresses (e.g. 10.0.0.1), CIDR notation (e.g. 10.0.0.1/24), or resolvable hostnames (e.g. foo.bar) to scan.

options:
  -h, --help            show this help message and exit
  -ct, --concurrent-targets <number>
                        The maximum number of target hosts to scan concurrently. Default: 5
  -cs, --concurrent-scans <number>
                        The maximum number of scans to perform per target host. Default: 10
  -V, --version         Display version information and exit
  -ops, --only-portscan
                        Only scan open ports and ips, enumeration services will NOT run. Default: False
  -p, --profile PROFILE
                        The port scanning profiles: default(TCP TOP1000),full(TCP 65535). Ex.bit00.py netscan <ipaddress> -p full Default: default
  -L, --list-plugins    List all available OSINT plugins
  -P, --plugin PLUGIN   Run specific plugin instead of full scan
  -v, --verbose         Enable verbose output. Repeat for more verbosity.
  -o, --output OUTPUTDIR
                        The output directory for results. Default: recon
  --only-scans-dir      Only create the "scans" directory for results. Other directories (e.g. exploit, loot, report) will not be created. Default: false
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

├── netscan.json
├── netscan.md
├── netscan.xml
├── osint.json
├── osint.xml
├── osint.md
├── osint
│   └── agetic.gob.bo
│       ├── logs
│       │   ├── commands.log
│       │   ├── error.log
│       │   └── patterns.log
│       └── scans
│           ├── info
│           │   ├── email_spiderfoot_agetic.gob.bo.ansi
│           │   ├── email_spiderfoot_ns.agetic.gob.bo.ansi
│           │   ├── email_spiderfoot_www.agetic.gob.bo.ansi
│           │   ├── geolocation_ipapi_186.121.242.37.json
│           │   ├── geolocation_ipapi_186.121.242.44.json
│           │   ├── geolocation_ipapi_186.121.242.45.json
│           │   ├── geolocation_ipapi_190.14.106.3.json
│           │   ├── geolocation_ipapi_190.14.106.6.json
│           │   ├── geolocation_ipapi_200.87.125.227.json
│           │   ├── geolocation_ipapi_200.87.125.234.json
│           │   └── geolocation_ipapi_agetic.gob.bo.json
│           ├── recon
│           │   ├── dns_fierce_agetic.gob.bo.ansi
│           │   ├── revdns_dig_agetic.gob.bo.ansi
│           │   ├── revdns_dnsrecon_190.14.106.3.csv
│           │   ├── revdns_dnsrecon_200.87.125.227.csv
│           │   ├── revdns_dnsrecon_agetic.gob.bo.csv
│           │   └── sublist3r_agetic.gob.bo.txt
│           └── tech
│               ├── net_asn_186.121.242.37.json
│               ├── net_asn_186.121.242.44.json
│               ├── net_asn_186.121.242.45.json
│               ├── net_asn_190.14.106.3.json
│               ├── net_asn_190.14.106.6.json
│               ├── net_asn_200.87.125.227.json
│               ├── net_asn_200.87.125.234.json
│               ├── web_spiderfoot_agetic.gob.bo.ansi
│               ├── web_spiderfoot_blog.agetic.gob.bo.ansi
│               ├── web_spiderfoot_capibara.agetic.gob.bo.ansi
│               ├── web_spiderfoot_test.agetic.gob.bo.ansi
│               └── web_spiderfoot_www.agetic.gob.bo.ansi

├── recon
│   ├── 190.181.15.42
│   │   ├── logs
│   │   │   ├── commands.log
│   │   │   └── error.log
│   │   └── scans
│   │       ├── gnmap
│   │       │   └── _top_1000_tcp_nmap.gnmap
│   │       ├── searchsploit-nmap-tcp.ansi
│   │       ├── _top_1000_tcp_masscan.txt
│   │       ├── _top_1000_tcp_nmap.txt
│   │       └── xml
│   │           └── _top_1000_tcp_nmap.xml
│   ├── 190.181.15.45
│   │   ├── logs
│   │   │   ├── commands.log
│   │   │   ├── error.log
│   │   │   └── patterns.log
│   │   └── scans
│   │       ├── gnmap
│   │       │   └── _top_1000_tcp_nmap.gnmap
│   │       ├── searchsploit-nmap-tcp.ansi
│   │       ├── _top_1000_tcp_masscan.txt
│   │       ├── _top_1000_tcp_nmap.txt
│   │       └── xml
│   │           └── _top_1000_tcp_nmap.xml
│   ├── 200.87.125.227
│   │   ├── logs
│   │   │   ├── commands.log
│   │   │   ├── error.log
│   │   │   └── patterns.log
│   │   └── scans
│   │       ├── _full_tcp_nmap.txt
│   │       ├── gnmap
│   │       │   ├── _full_tcp_nmap.gnmap
│   │       │   └── _top_1000_tcp_nmap.gnmap
│   │       ├── searchsploit-nmap-tcp.ansi
│   │       ├── tcp_143_imap_nmap.txt
│   │       ├── tcp_25_cassandra_nmap.txt
│   │       ├── tcp_25_distcc_nmap.txt
│   │       ├── tcp_587_sslscan.txt
│   │       ├── tcp_636_ldap_nmap.txt
│   │       ├── tcp_636_ldapssl_ldapanonymous.ansi
│   │       ├── tcp_636_ldapssl_ldapsearch.ansi
│   │       ├── tcp_636_ldapssl_netexec_notsigned.ansi
│   │       ├── tcp_636_sslscan.txt
│   │       ├── tcp_80_http_CMSeek.ansi
│   │       ├── tcp_80_sslscan.txt
│   │       ├── tcp_993_imap_nmap.txt
│   │       ├── tcp_993_irc_nmap.txt
│   │       ├── _top_1000_tcp_masscan.txt
│   │       ├── _top_1000_tcp_nmap.txt
│   │       └── xml
│   │           ├── _full_tcp_nmap.xml
│   │           └── _top_1000_tcp_nmap.xml
│   └── 200.87.125.234
│       ├── logs
│       │   ├── commands.log
│       │   ├── error.log
│       │   └── patterns.log
│       └── scans
│           ├── _full_tcp_nmap.txt
│           ├── gnmap
│           │   ├── _full_tcp_nmap.gnmap
│           │   └── _top_1000_tcp_nmap.gnmap
│           ├── searchsploit-nmap-tcp.ansi
│           ├── tcp_443_http_nmap.txt
│           ├── tcp_443_snmp_nmap.txt
│           ├── tcp_443_sslscan.txt
│           ├── tcp_80_cassandra_nmap.txt
│           ├── tcp_80_distcc_nmap.txt
│           ├── tcp_80_http_nmap.txt
│           ├── tcp_80_http_nuclei.txt
│           ├── _top_1000_tcp_masscan.txt
│           ├── _top_1000_tcp_nmap.txt
│           └── xml
│               ├── _full_tcp_nmap.xml
│               ├── tcp_443_https_nmap.xml
│               └── _top_1000_tcp_nmap.xml



```

The logs directory is where all masscan/nmap scans data will save. This information is only for the port-scan-profiles.toml's commands:

* \_commands.log contains a list of every command BIT00 ran against the target. This is useful if one of the commands fails and you want to run it again with modifications.

* If output matches a defined pattern, two files called \_sumportsrv.log and \_draft.log will also appear in the scans directory with details about the matched output.

* If a scan results in an error, a file called \_errors.log will also appear in the logs directory with some details to alert the user.

Scans directory:

* \_manual_commands.txt contains any commands that are deemed "too dangerous" to run automatically, either because they are too intrusive, require modification based on human analysis, or just work better when there is a human monitoring them.

> [!NOTE]
> BIT00 does NOT make any exploit o execute any PoC, its only reconnaissance!!!
