

PATTERNS = {
  "discover": {
    "HostEnum": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'^(?P<domain>[a-zA-Z0-9.-]+)(\s*)(has)(\s*)(address)(\s*)(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            }
        ],
        "DigEnum": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'^(?P<domain>[a-zA-Z0-9.-]+)\s+\d+\s+IN\s+A\s+(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            }
        ],
        "DNSRecon": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'(?:\[\*\]\s+\w+|\[\+\]\s+\w+)\s+(?P<domain>[a-zA-Z0-9.-]+)\s+(?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            }
        ],
        "Sublister": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'^(?P<domain>[a-zA-Z0-9.-]+)(?P<ipaddress>)'
            }
        ],
        "FirceRecon": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'^Found:\s*(?P<domain>[\w.-]+)\.\s*\((?P<ipaddress>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\)$'
            }
        ],
        "SubFinder": [
            {
            "description": "domain2ip: {match}",
            "pattern": r'^(?P<domain>[a-zA-Z0-9.-]+)(?P<ipaddress>)'
            }
        ] 
    },
    "revlookup": {
        "AmassRevlookup": [
            {
            "description": "revlookup: {match}",
            "pattern": "(.*)(\\\\t)(IP)(\\s*)(Address)(\\\\t)(?P<domain>(?![\\d.]+)((?!-))(xn--)?[a-z0-9][a-z0-9-_]{0,61}[a-z0-9]{0,1}\\.(xn--)?([a-z0-9\\._-]{1,61}|[a-z0-9-]{1,30})(\\\\t)(?P<ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}))"
            }
        ],
    "SpiderfootRevlookup": [
        {
        "description": "revlookup: {match}",
        "pattern": ".*(,)(?P<ipaddress>\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})(,)(?P<domain>[a-zA-Z0-9.-]+)$"
        }
        ]
    },
    "subdomain": {
        "SpiderfootWeb": [
            {
            "description": "webtech: {match}",
            "pattern": r'.*,Web Server,(\S+),((?!text/html|text/css).*)'
            },
            {
            "description": "webtech: {match}",
            "pattern": r'.*,Web Content Type,(\S+),((?!text/html|text/css).*)'
            }
        ],
        "SpiderfootEmail": [
            {
            "description": "email: {match}",
            "pattern": r'[\w.+-]+@[\w-]+\.[\w.-]+'
            }
        ],
    },
    "ipnet":{
        "CurlGeolocation": [
             {
            "description": "geoinfo: {match}",
            "pattern": r'"country"\s*:\s*"([^"]+)"'
             },
             {            
            "description": "geoinfo: {match}",
            "pattern": r'"city"\s*:\s*"([^"]+)"'
             },
            {
            "description": "geoinfo: {match}",
            "pattern": r'"isp"\s*:\s*"([^"]+)"'
            },
            {
            "description": "geoinfo: {match}",
            "pattern": r'"as"\s*:\s*"([^"]+)"'
            }
        ],
        "DNSReconRegisters": [
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]NS\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]A\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]MX\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]SOA\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=spf.*)'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=spf.*)'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=DMAR.*)'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]PTR\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            }
        ],
        "AsnNet": [        
            {    
            "description": "ostech: {match}",
            "pattern": r'cpe:(?:/a:)?(.*)$'
            },
            {
            "description": "cve: {match}",
            "pattern": r'(CVE-\d{4}-\d{4,7})'
            }
        ],
        "SublisterPorts": [        
            {    
            "description": "tcpports: {match}",
            "pattern": r'(.*Found open ports:.*)'
            }
        ]
    }
}
