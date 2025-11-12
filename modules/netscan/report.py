import os
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
import re
from helpers.io import error, info, debug, warn

def generate_reports(patterns_log_paths, output_dir):
    """Generate NETSCAN reports from multiple patterns.log files"""
    debug(f"Generating NETSCAN reports from {len(patterns_log_paths)} log files")
    
    parser = NetScanParser()
    
    # Parse data from all log files
    all_netscan_data = defaultdict(lambda: defaultdict(list))
    
    for log_path in patterns_log_paths:
        debug(f"Processing NETSCAN log: {log_path}")
        if not os.path.exists(log_path):
            error(f"  Log file not found: {log_path}")
            continue
            
        file_size = os.path.getsize(log_path)
        debug(f"  Log file size: {file_size} bytes")
        
        netscan_data = parser.parse_netscan_data(log_path)
        
        if not netscan_data:
            error(f"  No NETSCAN data found in: {log_path}")
            continue
            
        # Merge data from all logs
        for ip, data in netscan_data.items():
            debug(f"  Found target: {ip} with {len(data.get('services', []))} services")
            
            # Only update OS/TTL if not already set or if we have better info
            if 'os' not in all_netscan_data[ip] or all_netscan_data[ip]['os'] == 'Unknown':
                if 'os' in data and data['os'] != 'Unknown':
                    all_netscan_data[ip]['os'] = data['os']
            
            if 'ttl' not in all_netscan_data[ip] or all_netscan_data[ip]['ttl'] == 'Unknown':
                if 'ttl' in data and data['ttl'] != 'Unknown':
                    all_netscan_data[ip]['ttl'] = data['ttl']
            
            # Merge services
            all_netscan_data[ip]['services'].extend(data.get('services', []))
    
    info("Total IPs found: {byellow}{total_ips}{rst}", total_ips =len(all_netscan_data))
    
    if not all_netscan_data:
        error("No NETSCAN data found in any log files!")
        # Create empty reports with message
        create_empty_reports(output_dir, "netscan", "No NETSCAN data found in log files")
        return
    
    # Remove duplicates before generating reports
    all_netscan_data = remove_duplicates(all_netscan_data)
    
    # Generate reports with merged and deduplicated data
    generate_netscan_text(all_netscan_data, output_dir)
    generate_netscan_json(all_netscan_data, output_dir)
    generate_netscan_xml(all_netscan_data, output_dir)

def remove_duplicates(netscan_data):
    """Remove duplicate services from NETSCAN data"""
    debug("Removing duplicate services...")
    
    deduplicated_data = defaultdict(lambda: defaultdict(list))
    duplicate_count = 0
    
    for ip, data in netscan_data.items():
        # Copy OS and TTL information
        deduplicated_data[ip]['os'] = data.get('os', 'Unknown')
        deduplicated_data[ip]['ttl'] = data.get('ttl', 'Unknown')
        
        # Use a set to track unique services
        seen_services = set()
        unique_services = []
        
        for service in data.get('services', []):
            # Create a unique identifier for the service
            plugin, context = service
            service_key = f"{plugin}:{context}"
            
            if service_key not in seen_services:
                seen_services.add(service_key)
                unique_services.append(service)
            else:
                duplicate_count += 1
                debug(f"  Removed duplicate service for {ip}: {service_key}")
        
        deduplicated_data[ip]['services'] = unique_services
        
        original_count = len(data.get('services', []))
        unique_count = len(unique_services)
        if original_count != unique_count:
            debug(f"  Target {ip}: {original_count} -> {unique_count} services (removed {original_count - unique_count} duplicates)")
    
    debug(f"Removed {duplicate_count} duplicate services total")
    return deduplicated_data

class NetScanParser:
    def __init__(self):
        self.netscan_data = defaultdict(lambda: defaultdict(list))

    def parse_netscan_data(self, patterns_log_path):
        """Parse NETSCAN data from a single patterns.log file"""
        netscan_entries = 0
    
        try:
            with open(patterns_log_path, 'r', encoding='utf-8', errors='ignore') as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue
                
                    # Debug: print first few lines to understand format
                    if line_num <= 3:
                        debug(f"    Line {line_num}: {line}")
                
                    # Remove the initial [*] 
                    if line.startswith('[*] '):
                        line = line[4:]  # Remove "[*] "
                
                    # Parse the line
                    pattern = r'^\[([^\]]+)\]:([^:]+):([^:]+):([^:]+):([^:]+):([^:]+):?(.*)$'
                    match = re.match(pattern, line)
                
                    if not match:
                        debug(f"    ✗ Line {line_num} doesn't match expected format")
                        continue
                
                    # Extract all groups
                    timestamp = match.group(1)  # "20251109:21.53.15"
                    phase = match.group(2)      # "portscan" or "scans"
                    plugin = match.group(3)     # "NmapTCPTop1000" or "NmapHttp"
                    field4 = match.group(4)
                    field5 = match.group(5)
                    field6 = match.group(6)
                    field7 = match.group(7)     # Will be empty string if not present
                
                    # Handle different phases
                    if phase == 'portscan':
                        # Format: [timestamp]:portscan:plugin:ip:portscan:service_details
                        ip_address = field4
                        context = field5
                        service_details = field6
                    
                        netscan_entries += 1
                        self._process_netscan_entry(plugin, context, ip_address, service_details)
                        debug(f"    Processed NETSCAN entry #{netscan_entries}")
                    
                    elif phase == 'scans':
                        # Format: [timestamp]:scans:plugin:service:ip:flag:details
                        service = field4        # "tcp/443/https"
                        ip_address = field5     # "200.87.125.227"
                        flag_type = field6      # "vuln" or "cve"
                        details = field7        # "State: VULNERABLE" or "CVE-2011-3192"
                    
                        debug(f"    {flag_type.upper()} Found - Plugin: '{plugin}', Target: '{ip_address}', Service: '{service}'")
                        debug(f"    {flag_type.upper()} Details: {details}")
                    
                        # Store vulnerability information
                        if ip_address not in self.netscan_data:
                            self.netscan_data[ip_address] = {'os': 'Unknown', 'ttl': None, 'services': []}
                    
                        if flag_type == 'cve':
                            self.netscan_data[ip_address]['services'].append((plugin, f"CVE: {details}"))
                        elif flag_type == 'vuln':
                            self.netscan_data[ip_address]['services'].append((plugin, f"VULN: {details}"))
                        elif flag_type == 'tech':
                            self.netscan_data[ip_address]['services'].append((plugin, f"TECH: {details}"))

                    else:
                        debug(f"    Skipping - unknown phase: '{phase}'")

            debug(f"  Processed {netscan_entries} NETSCAN entries")
        
        except Exception as e:
            error(f"  Error parsing log file: {e}")
            import traceback
            traceback.print_exc()
    
        return self.netscan_data

    def _process_netscan_entry(self, plugin, context, ip_address, service_details):
        """Process a single NETSCAN entry"""
        # Validate IP address
        #if not self._is_valid_ip(ip_address):
        #    debug(f"\tInvalid IP: {ip_address}")
        #    return
        if not self._is_valid_target(ip_address):
            debug(f"\tInvalid target: {ip_address}")
            return

        # Extract TTL from service_details (look for numbers at the end)
        ttl = self._extract_ttl(service_details)
        os_type = "Linux" if ttl and ttl < 64 else "Windows" if ttl else "Unknown"
        
        print(ttl)
        # Store the data
        self.netscan_data[ip_address]['os'] = os_type
        self.netscan_data[ip_address]['ttl'] = ttl

        # Create service description
        if context == 'portscan':
            service_desc = f"portscan:{service_details}"
        elif context in ['vuln', 'cve', 'tech']:
            service_desc = f"{context}:{service_details}"
        else:
            service_desc = f"{context}:{service_details}"
        
        self.netscan_data[ip_address]['services'].append((plugin, service_desc))
        
        debug(f"\tAdded service for {ip_address}: {plugin} - {service_desc} (TTL: {ttl}, OS: {os_type})")

    def _is_valid_ip(self, ip):
        """Check if the string is a valid IP address"""
        ip_pattern = r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$'
        return re.match(ip_pattern, ip) is not None

    def _is_valid_domain(self, domain):
        """Check if the address is a valid domain name."""
        if not domain or len(domain) > 253:
            return False
        
        # Basic domain pattern validation
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, domain))
    
    def _is_valid_target(self, address):
        """Check if the address is a valid IP or domain."""
        return self._is_valid_ip(address) or self._is_valid_domain(address)

    def _extract_ttl(self, service_details):
        """Extract TTL value from service details"""
        if not service_details:
            return None
    
        # Priority 1: TTL in parentheses (most common in nmap output)
        ttl_patterns = [
            r'\((\d{1,3})\)\s*$',    # Numbers in parentheses at end
            r'\bttl[=\s:]*(\d+)',    # ttl=64, ttl: 128
            r'\bTTL[=\s:]*(\d+)',    # TTL=64, TTL: 128
        ]
    
        for pattern in ttl_patterns:
            match = re.search(pattern, service_details, re.IGNORECASE)
            if match:
                try:
                    ttl = int(match.group(1))
                    if 1 <= ttl <= 255:
                        return ttl
                except ValueError:
                    continue
    
        return None

def generate_netscan_text(netscan_data, output_dir):
    """Generate NETSCAN TXT Results"""
    content = ["[*] NETSCAN Port Enumeration Results", ""]    

    if not netscan_data:
        content.append("[-] No NETSCAN data available.")
    else:
        for ip, data in netscan_data.items():
            ttl = data.get('ttl', 'Unknown')
            os_type = data.get('os', 'Unknown')
            content.append(f"[+] {ip} (ttl={ttl}, OS={os_type}):")
            
            services = data.get('services', [])
            if services:
                for plugin, context in services:
                    content.append(f"\t[{plugin}] {context}")
            else:
                content.append("\tNo services found")
            content.append("")
    
    output_path = os.path.join(output_dir, "netscan.txt")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))
    info("NETSCAN TXT report generated: {bgreen}{output_path}{rst}")


def generate_netscan_json(netscan_data, output_dir):
    """Generate NETSCAN JSON report"""
    report = {"NETSCAN": {}}
    
    if netscan_data:
        for ip, data in netscan_data.items():
            ttl = data.get('ttl', 'Unknown')
            os_type = data.get('os', 'Unknown')
            
            # Create IP entry with OS info
            report["NETSCAN"][ip] = {
                "OS": f"{os_type} (ttl={ttl})"
            }
            
            # Add services as separate objects in an array
            services_list = []
            for plugin, context in data.get('services', []):
                service_obj = {
                    plugin: context
                }
                services_list.append(service_obj)
            
            # Add services array to the IP entry
            report["NETSCAN"][ip]["services"] = services_list
    
    output_path = os.path.join(output_dir, "netscan.json")
    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    info("NETSCAN JSON report generated: {bgreen}{output_path}{rst}")

def generate_netscan_xml(netscan_data, output_dir):
    """Generate NETSCAN XML report"""
    root = ET.Element("NETSCAN")
    
    if netscan_data:
        for ip, data in netscan_data.items():
            ip_elem = ET.SubElement(root, "host")
            ET.SubElement(ip_elem, "ip_address").text = ip
            ET.SubElement(ip_elem, "os").text = data.get('os', 'Unknown')
            ET.SubElement(ip_elem, "ttl").text = str(data.get('ttl', 'Unknown'))
            
            services_elem = ET.SubElement(ip_elem, "services")
            for plugin, context in data.get('services', []):
                service_elem = ET.SubElement(services_elem, "service")
                ET.SubElement(service_elem, "plugin").text = plugin
                ET.SubElement(service_elem, "details").text = context
    else:
        ET.SubElement(root, "message").text = "No NETSCAN data available"
    
    output_path = os.path.join(output_dir, "netscan.xml")
    tree = ET.ElementTree(root)
    tree.write(output_path, encoding='utf-8', xml_declaration=True)
    info("NETSCAN XML report generated: {bgreen}{output_path}{rst}")

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
    
    warn(f"Created empty {report_type} reports with message: {message}")