PATTERNS = {
    "portscan": {
        "MasscanFull": [
            {
            "description": "portscan: {match}",
            "pattern": r'^Discovered\s+open\s+port\s*(?P<port>\d+)/(?:tcp)\b'
            }
        ],
        "NmapTCPFull": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>[A-Za-z0-9_.+-]+)\s*(?P<version>.*)$'
            }
        ],
        "MasscanTop1000": [
            {
            "description": "portscan: {match}",
            "pattern": r'^Discovered\s+open\s+port\s*(?P<port>\d+)/(?:tcp)\b'
            }
        ],
        "NmapTCPTop1000": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>[A-Za-z0-9_.+-]+)\s*(?P<version>.*)$'
            }
        ]
    },
    "scans": {
        "Nuclei": [
            {
                'description': 'tech: {match}',
                'pattern': r'^\[.*-detect.*'
            },
            {
                'description': 'tech: {match}',
                'pattern': r'^\[azure-domain-tenant\].*'
            },
            {
                'description': 'vuln: {match}',
                'pattern': r'.*\[vuln\].*'
            },
            {
                'description': 'vuln: {match}',
                'pattern': r'.*\[medium\].*'
            },
            {
                'description': 'vuln: {match}',
                'pattern': r'.*\[high\].*'
            },
            {
                'description': 'cve: {match}',
                'pattern': r'^\[CVE-.*'
            }
        ],
        "Cmseek": [
            {
                'description': 'tech: {match}',
                'pattern': r'Version Detected.*'
            }
        ],
        "DNSReconRegisters": [
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]NS\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "dnsenum: {match}",
            "pattern": r'([ \t ]CNAME\s.*)'
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
        "GlobalPatterns": [
            {
                'description': 'vuln: {match}',
                'pattern': r'State: (?:(?:LIKELY\_?)?VULNERABLE)'
            },
            {
                'description': 'vuln: {match})', 
                'pattern': r'(?i)unauthorized'
            },
            {
                'description': 'cve: {match}',
                'pattern': r'(CVE-\d{4}-\d{4,7})'
            },
            {
                'description': 'vuln: {match}',
                'pattern': r'Anonymous FTP login allowed'
            }
        ]
    }
}

