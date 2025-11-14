PATTERNS = {
    "portscan": {
        "NaabuTCPFull": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>\S+)\s*(?P<version>.*)$'
            }
        ],
        "NmapTCPFull": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>\S+)\s*(?P<version>.*)$'
            }
        ],
        "NaabuTCPTop1000": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>\S+)\s*(?P<version>.*)$'
            }
        ],
        "NmapTCPTop1000": [
            {
            "description": "portscan: {match}",
            "pattern": r'^(?P<port>\d+)/(?:)(?P<protocol>tcp|udp)\s+\S+\s+(?P<service>\S+)\s*(?P<version>.*)$'
            }
        ]
    },
    "scans": {
        "Cmseek": [
            {
                'description': 'TECH: {match}',
                'pattern': r'Version Detected.*'
            }
        ],
        "DNSRegistersRecon": [
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]NS\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]CNAME\s.*)'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]A\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]MX\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]SOA\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=spf.*)'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=spf.*)'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]TXT\s.*\sv=DMAR.*)'
            },
            {
            "description": "TECH: {match}",
            "pattern": r'([ \t ]PTR\s.*\s\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'
            }
        ],
        "GlobalPatterns": [
            {
                'description': 'VULN: {match}',
                'pattern': r'State: (?:(?:LIKELY\_?)?VULNERABLE)'
            },
            {
                'description': 'VULN: {match})', 
                'pattern': r'(?i)unauthorized'
            },
            {
                'description': 'CVE: {match}',
                'pattern': r'(CVE-\d{4}-\d{4,7})'
            },
            {
                'description': 'VULN: {match}',
                'pattern': r'Anonymous FTP login allowed'
            },{
                'description': 'TECH: {match}',
                'pattern': r'^\[.*-detect.*'
            },
            {
                'description': 'TECH: {match}',
                'pattern': r'^\[azure-domain-tenant\].*'
            },
            {
                'description': 'VULN: {match}',
                'pattern': r'.*\[vuln\].*'
            },
            {
                'description': 'VULN: {match}',
                'pattern': r'.*\[medium\].*'
            },
            {
                'description': 'VULN: {match}',
                'pattern': r'.*\[high\].*'
            },
            {
                'description': 'VULN: {match}',
                'pattern': r'.*\[critical\].*'
            },
            {
                'description': 'CVE: {match}',
                'pattern': r'^\[CVE-.*'
            }
        ]
    }
}

