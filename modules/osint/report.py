import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
import re
from helpers.io import error, debug, warn, info

def generate_reports(patterns_log_paths, output_dir):
    """Generate OSINT reports from multiple patterns.log files"""
    debug(f"Generating OSINT reports from {len(patterns_log_paths)} log files")
    
    parser = OSINTParser()
    
    # Parse data from all log files
    all_osint_data = defaultdict(lambda: defaultdict(list))
    all_basedomains = set()
    
    for log_path in patterns_log_paths:
        debug(f"Processing OSINT log: {log_path}")
        if not os.path.exists(log_path):
            print(f"  ✗ Log file not found: {log_path}")
            continue
            
        file_size = os.path.getsize(log_path)
        debug(f"  ✓ Log file size: {file_size} bytes")
        
        osint_data, basedomains = parser.parse_osint_data(log_path)
        
        for domain in basedomains:
            all_basedomains.add(domain)
        
        if not osint_data:
            error(f"  ⚠ No OSINT data found in: {log_path}")
            continue
            
        # Merge data from all logs
        for target, data in osint_data.items():
            debug(f"  Found target: {target} with {sum(len(entries) for entries in data.values())} entries")
            for data_type, entries in data.items():
                # Add only unique entries
                for entry in entries:
                    if not _is_duplicate_entry(all_osint_data[target][data_type], entry):
                        all_osint_data[target][data_type].append(entry)
    
    #info("Base domains: {byellow}{base_domain}{rst}", base_domain=list(all_basedomains))
    info("Total subdomains found: {byellow}{num}{rst}", num=len(all_osint_data))
    
    if not all_osint_data:
        error("⚠ No OSINT data found in any log files!")
        # Create empty reports with message
        create_empty_reports(output_dir, "osint", "No OSINT data found in log files")
        return
    
    # Generate reports with merged data
    generate_osint_markdown(all_osint_data, all_basedomains, output_dir)
    generate_osint_json(all_osint_data, all_basedomains, output_dir)
    generate_osint_xml(all_osint_data, all_basedomains, output_dir)

def _is_duplicate_entry(existing_entries, new_entry):
    """Check if an entry already exists in the list"""
    for existing_entry in existing_entries:
        if (existing_entry.get('plugin') == new_entry.get('plugin') and 
            existing_entry.get('content') == new_entry.get('content') and
            existing_entry.get('email') == new_entry.get('email')):
            return True
    return False

class OSINTParser:
    def __init__(self):
        self.osint_data = defaultdict(lambda: defaultdict(list))
        self.basedomains = set()
        self.ip_to_hostname = {}
        self.processed_entries = set()  # Track processed entries to avoid duplicates

    def parse_osint_data(self, patterns_log_path):
        """Parse OSINT data from a single patterns.log file"""
        osint_entries = 0
        
        try:
            with open(patterns_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                    
                    # Create a unique identifier for this line to avoid duplicates
                    line_hash = hash(line)
                    if line_hash in self.processed_entries:
                        continue
                    self.processed_entries.add(line_hash)
                    
                    # Parse the actual log format: 
                    # [*] [20251108:16.19.21]:ipnet:DNSReconRegisters:agetic.gob.bo:dnsenum: A agetic.gob.bo 190.14.106.3
                    
                    # Remove the initial [*] 
                    if line.startswith('[*] '):
                        line = line[4:]  # Remove "[*] "
                    
                    # NEW APPROACH: Use regex to extract the components properly
                    # Format: [timestamp]:phase:plugin:target:desc:content
                    pattern = r'^\[([^\]]+)\]:([^:]+):([^:]+):([^:]+):([^:]+):(.+)$'
                    match = re.match(pattern, line)
                    
                    if not match:
                        continue
                    
                    # Extract components from regex groups
                    timestamp = match.group(1)  # "20251108:16.19.21"
                    phase = match.group(2)      # "ipnet", "discover", "subdomain"
                    plugin = match.group(3)     # "DNSReconRegisters", "DigEnum", "SpiderfootEmail"
                    target = match.group(4)     # "agetic.gob.bo", "190.14.106.3", etc.
                    desc = match.group(5)       # "dnsenum", "domain2ip", "email", "geoinfo", etc.
                    content = match.group(6)    # "A agetic.gob.bo 190.14.106.3", "jhonnatan.lacoa@agetic.gob.bo", etc.
                    
                    # Process all OSINT phases
                    osint_entries += 1
                    self._process_osint_entry(plugin, desc, target, content)
            
            debug(f"  Processed {osint_entries} OSINT entries")
            
        except Exception as e:
            error(f"  ✗ Error parsing log file: {e}")
            import traceback
            traceback.print_exc()
        
        return self.osint_data, self.basedomains

    def _process_osint_entry(self, plugin, desc, target, content):
        """Process a single OSINT entry"""
        # Extract base domain from target
        base_domain = self._extract_base_domain(target)
        if base_domain:
            self.basedomains.add(base_domain)
        
        # Process based on description type
        if desc == 'email':
            self._process_email(plugin, target, content)
        elif desc == 'domain2ip':
            self._process_domain2ip(plugin, target, content)
        elif desc == 'dnsenum':
            self._process_dnsenum(plugin, target, content)
        elif desc == 'geoinfo':
            self._process_geoinfo(plugin, target, content)
        elif desc in ['tech', 'ostech', 'webtech']:
            self._process_tech(plugin, desc, target, content)

    def _process_email(self, plugin, target, content):
        """Process email entries"""
        # content: "jhonnatan.lacoa@agetic.gob.bo"
        email_match = re.search(r'([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})', content)
        if email_match:
            email = email_match.group(1)
            domain = email.split('@')[1]
            base_domain = self._extract_base_domain(domain)
            
            if base_domain:
                entry = {
                    'plugin': plugin,
                    'email': email,
                    'content': email
                }
                # Check for duplicates before adding
                if not self._is_duplicate_in_list(self.osint_data[base_domain]['email'], entry):
                    self.osint_data[base_domain]['email'].append(entry)

    def _process_domain2ip(self, plugin, target, content):
        """Process domain to IP mapping entries"""
        # content: "190.14.106.3-www.agetic.gob.bo"
        match = re.search(r'([\d.]+)-([\w.-]+)', content)
        if match:
            ip, hostname = match.groups()
            
            # Store IP to hostname mapping
            self.ip_to_hostname[ip] = hostname
            
            # Extract base domain
            base_domain = self._extract_base_domain(hostname)
            if base_domain:
                self.basedomains.add(base_domain)
            
            # Add to osint_data
            target_key = f"{hostname}:{ip}"
            entry = {
                'plugin': plugin,
                'content': content[:80]  # Limit content length
            }
            # Check for duplicates before adding
            if not self._is_duplicate_in_list(self.osint_data[target_key]['host'], entry):
                self.osint_data[target_key]['host'].append(entry)

    def _process_dnsenum(self, plugin, target, content):
        """Process DNS enumeration entries"""
        # content: "A agetic.gob.bo 190.14.106.3"
        base_domain = self._extract_base_domain(target)
        if base_domain:
            entry = {
                'plugin': plugin,
                'content': content[:80]  # Limit content length
            }
            # Check for duplicates before adding
            if not self._is_duplicate_in_list(self.osint_data[base_domain]['dnsenum'], entry):
                self.osint_data[base_domain]['dnsenum'].append(entry)

    def _process_geoinfo(self, plugin, target, content):
        """Process geolocation entries"""
        # content: 'country":"Bolivia'
        # Check if target is an IP address
        if self._is_valid_ip(target):
            ip = target
            hostname = self.ip_to_hostname.get(ip)
            if hostname:
                target_key = f"{hostname}:{ip}"
            else:
                target_key = f"unknown:{ip}"
            
            entry = {
                'plugin': plugin,
                'content': content[:80]  # Limit content length
            }
            # Check for duplicates before adding
            if not self._is_duplicate_in_list(self.osint_data[target_key]['geoinfo'], entry):
                self.osint_data[target_key]['geoinfo'].append(entry)
        else:
            # Target is a domain
            base_domain = self._extract_base_domain(target)
            if base_domain:
                entry = {
                    'plugin': plugin,
                    'content': content[:80]  # Limit content length
                }
                # Check for duplicates before adding
                if not self._is_duplicate_in_list(self.osint_data[base_domain]['geoinfo'], entry):
                    self.osint_data[base_domain]['geoinfo'].append(entry)

    def _process_tech(self, plugin, desc, target, content):
        """Process technology entries (tech, ostech, webtech)"""
        # Check if target is an IP address
        if self._is_valid_ip(target):
            ip = target
            hostname = self.ip_to_hostname.get(ip)
            if hostname:
                target_key = f"{hostname}:{ip}"
            else:
                target_key = f"unknown:{ip}"
            
            entry = {
                'plugin': plugin,
                'content': content[:90]  # Limit content length
            }
            # Check for duplicates before adding
            if not self._is_duplicate_in_list(self.osint_data[target_key][desc], entry):
                self.osint_data[target_key][desc].append(entry)
        else:
            # Target is a domain
            base_domain = self._extract_base_domain(target)
            if base_domain:
                entry = {
                    'plugin': plugin,
                    'content': content[:90]  # Limit content length
                }
                # Check for duplicates before adding
                if not self._is_duplicate_in_list(self.osint_data[base_domain][desc], entry):
                    self.osint_data[base_domain][desc].append(entry)

    def _is_duplicate_in_list(self, entry_list, new_entry):
        """Check if an entry already exists in the list"""
        for entry in entry_list:
            if (entry.get('plugin') == new_entry.get('plugin') and 
                entry.get('content') == new_entry.get('content') and
                entry.get('email') == new_entry.get('email')):
                return True
        return False

    def _extract_base_domain(self, domain):
        """Extract base domain from full domain"""
        if self._is_valid_ip(domain):
            return None
            
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain

    def _is_valid_ip(self, ip):
        """Check if the string is a valid IP address"""
        ip_pattern = r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$'
        return re.match(ip_pattern, ip) is not None

def generate_osint_markdown(osint_data, basedomains, output_dir):
    """Generate OSINT markdown report"""
    content = ["# OSINT REPORT", ""]
    
    if not osint_data:
        content.append("No OSINT data available.")
    else:
        # Process each base domain
        for basedomain in sorted(basedomains):
            content.append("# OSINT")
            content.append(f"BASEDOMAIN: {basedomain}")
            
            # Add email entries for base domain
            if basedomain in osint_data and 'email' in osint_data[basedomain]:
                for entry in osint_data[basedomain]['email']:
                    content.append(f"\t[{entry['plugin']}] email: {entry.get('email', entry.get('content', ''))}")
            
            # Add DNS enumeration entries for base domain
            if basedomain in osint_data and 'dnsenum' in osint_data[basedomain]:
                for entry in osint_data[basedomain]['dnsenum']:
                    content.append(f"\t[{entry['plugin']}] dnsenum: {entry.get('content', '')}")
            
            # Add webtech entries for base domain
            if basedomain in osint_data and 'webtech' in osint_data[basedomain]:
                for entry in osint_data[basedomain]['webtech']:
                    content.append(f"\t[{entry['plugin']}] tech: {entry.get('content', '')}")
            
            content.append("")
        
        # Add host entries (hostname:ip format)
        for target in sorted(osint_data.keys()):
            if ':' not in target:
                continue  # Skip base domains we already processed
                
            hostname, ip = target.split(':')
            content.append(f"[+] {hostname}:{ip}")
            
            # Technology entries
            if 'tech' in osint_data[target]:
                for entry in osint_data[target]['tech']:
                    content.append(f"\t[{entry['plugin']}] tech: {entry.get('content', '')}")
            
            # OS Technology entries
            if 'ostech' in osint_data[target]:
                for entry in osint_data[target]['ostech']:
                    content.append(f"\t[{entry['plugin']}] ostech: {entry.get('content', '')}")
            
            # Geolocation entries
            if 'geoinfo' in osint_data[target]:
                for entry in osint_data[target]['geoinfo']:
                    content.append(f"\t[{entry['plugin']}] geoinfo: {entry.get('content', '')}")
            
            # Host-specific entries
            if 'host' in osint_data[target]:
                for entry in osint_data[target]['host']:
                    content.append(f"\t[{entry['plugin']}] host: {entry.get('content', '')}")
            
            content.append("")
    
    output_path = os.path.join(output_dir, "osint.md")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))
    info("OSINT Markdown report generated: {bgreen}{output_path}{rst}")

def generate_osint_json(osint_data, basedomains, output_dir):
    """Generate OSINT JSON report"""
    report = {"OSINT": {
        "basedomains": list(basedomains),
        "basedomain_data": {},
        "hosts": {}
    }}
    
    if osint_data:
        # Base domain data
        for basedomain in basedomains:
            if basedomain in osint_data:
                report["OSINT"]["basedomain_data"][basedomain] = {}
                for data_type, entries in osint_data[basedomain].items():
                    report["OSINT"]["basedomain_data"][basedomain][data_type] = [
                        {"plugin": entry['plugin'], "content": entry.get('content', entry.get('email', ''))} 
                        for entry in entries
                    ]
        
        # Host data
        for target in osint_data:
            if ':' in target:
                hostname, ip = target.split(':')
                report["OSINT"]["hosts"][target] = {
                    "hostname": hostname,
                    "ip": ip,
                    "data": {}
                }
                for data_type, entries in osint_data[target].items():
                    report["OSINT"]["hosts"][target]["data"][data_type] = [
                        {"plugin": entry['plugin'], "content": entry.get('content', '')} 
                        for entry in entries
                    ]
    
    output_path = os.path.join(output_dir, "osint.json")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    info("OSINT JSON report generated: {bgreen}{output_path}{rst}")

def generate_osint_xml(osint_data, basedomains, output_dir):
    """Generate OSINT XML report"""
    root = ET.Element("OSINT")
    
    # Add basedomains
    basedomains_elem = ET.SubElement(root, "basedomains")
    for basedomain in basedomains:
        basedomain_elem = ET.SubElement(basedomains_elem, "basedomain")
        basedomain_elem.text = basedomain
        
        # Add basedomain data
        if basedomain in osint_data:
            basedata_elem = ET.SubElement(root, "basedomain_data")
            basedata_elem.set("domain", basedomain)
            for data_type, entries in osint_data[basedomain].items():
                for entry in entries:
                    entry_elem = ET.SubElement(basedata_elem, "entry")
                    ET.SubElement(entry_elem, "type").text = data_type
                    ET.SubElement(entry_elem, "plugin").text = entry['plugin']
                    ET.SubElement(entry_elem, "content").text = entry.get('content', entry.get('email', ''))
    
    # Add hosts
    hosts_elem = ET.SubElement(root, "hosts")
    for target in osint_data:
        if ':' in target:
            host_elem = ET.SubElement(hosts_elem, "host")
            hostname, ip = target.split(':')
            ET.SubElement(host_elem, "hostname").text = hostname
            ET.SubElement(host_elem, "ip").text = ip
            
            data_elem = ET.SubElement(host_elem, "data")
            for data_type, entries in osint_data[target].items():
                for entry in entries:
                    entry_elem = ET.SubElement(data_elem, "entry")
                    ET.SubElement(entry_elem, "type").text = data_type
                    ET.SubElement(entry_elem, "plugin").text = entry['plugin']
                    ET.SubElement(entry_elem, "content").text = entry.get('content', '')
    
    output_path = os.path.join(output_dir, "osint.xml")
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    info("OSINT XML report generated: {bgreen}{output_path}{rst}")

def create_empty_reports(output_dir, report_type, message):
    """Create empty reports with a message"""
    # Markdown
    md_path = os.path.join(output_dir, f"{report_type}.md")
    with open(md_path, 'w') as f:
        f.write(f"# {report_type.upper()} Report\n\n{message}\n")
    
    # JSON
    json_path = os.path.join(output_dir, f"{report_type}.json")
    with open(json_path, 'w') as f:
        json.dump({report_type.upper(): {"message": message}}, f, indent=2)
    
    # XML
    xml_path = os.path.join(output_dir, f"{report_type}.xml")
    root = ET.Element(report_type.upper())
    ET.SubElement(root, "message").text = message
    tree = ET.ElementTree(root)
    tree.write(xml_path, encoding='utf-8', xml_declaration=True)
    
    error(f"⚠ Created empty {report_type} reports with message: {message}")