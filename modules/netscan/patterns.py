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

