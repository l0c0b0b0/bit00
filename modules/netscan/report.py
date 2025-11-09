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
            debug(f"  Found IP: {ip} with {len(data.get('services', []))} services")
            
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
    generate_netscan_markdown(all_netscan_data, output_dir)
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
            debug(f"  IP {ip}: {original_count} -> {unique_count} services (removed {original_count - unique_count} duplicates)")
    
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
                    
                    # Parse the actual log format: 
                    # [*] [20251107:22.48.40]:portscan:NmapTCPTop1000:200.87.125.227:portscan:tcp/143/imap-Dovecot imapd54
                    
                    # Remove the initial [*] 
                    if line.startswith('[*] '):
                        line = line[4:]  # Remove "[*] "
                    
                    # NEW APPROACH: Use regex to extract the components properly
                    # Format: [timestamp]:phase:plugin:ip:context:service_details
                    pattern = r'^\[([^\]]+)\]:([^:]+):([^:]+):([^:]+):([^:]+):(.+)$'
                    match = re.match(pattern, line)
                    
                    if not match:
                        debug(f"    ✗ Line {line_num} doesn't match expected format")
                        continue
                    
                    # Extract components from regex groups
                    timestamp = match.group(1)  # "20251107:22.48.40"
                    phase = match.group(2)      # "portscan"
                    plugin = match.group(3)     # "NmapTCPTop1000"
                    ip_address = match.group(4) # "200.87.125.227"
                    context = match.group(5)    # "portscan" or "vuln" or "cve"
                    service_details = match.group(6) # "tcp/143/imap-Dovecot imapd54"
                    
                    debug(f"    Parsed - Phase: '{phase}', Plugin: '{plugin}', IP: '{ip_address}'")
                    
                    # Only process NETSCAN phases
                    if phase == 'portscan':
                        netscan_entries += 1
                        self._process_netscan_entry(plugin, context, ip_address, service_details)
                        debug(f"    Processed NETSCAN entry #{netscan_entries}")
                    else:
                        debug(f"    Skipping - not portscan phase: '{phase}'")
            
            debug(f"  Processed {netscan_entries} NETSCAN entries")
            
        except Exception as e:
            error(f"  Error parsing log file: {e}")
            import traceback
            traceback.print_exc()
        
        return self.netscan_data

    def _process_netscan_entry(self, plugin, context, ip_address, service_details):
        """Process a single NETSCAN entry"""
        # Validate IP address
        if not self._is_valid_ip(ip_address):
            debug(f"    Invalid IP: {ip_address}")
            return
        
        # Extract TTL from service_details (look for numbers at the end)
        ttl = self._extract_ttl(service_details)
        os_type = "Linux" if ttl and ttl < 64 else "Windows" if ttl else "Unknown"
        
        # Store the data
        self.netscan_data[ip_address]['os'] = os_type
        self.netscan_data[ip_address]['ttl'] = ttl
        
        # Create service description
        if context == 'portscan':
            service_desc = f"portscan:{service_details}"
        elif context in ['vuln', 'cve']:
            service_desc = f"{context}:{service_details}"
        else:
            service_desc = f"{context}:{service_details}"
        
        self.netscan_data[ip_address]['services'].append((plugin, service_desc))
        
        debug(f"    Added service for {ip_address}: {plugin} - {service_desc} (TTL: {ttl}, OS: {os_type})")

    def _is_valid_ip(self, ip):
        """Check if the string is a valid IP address"""
        ip_pattern = r'^\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b$'
        return re.match(ip_pattern, ip) is not None

    def _extract_ttl(self, service_details):
        """Extract TTL value from service details"""
        # Look for 2-digit numbers at the end of the string
        # Example: "tcp/143/imap-Dovecot imapd54" -> extract 54
        if service_details and len(service_details) >= 2:
            last_two = service_details[-2:]
            if last_two.isdigit():
                try:
                    ttl = int(last_two)
                    # TTL should be between 1 and 255
                    if 1 <= ttl <= 255:
                        return ttl
                except ValueError:
                    pass
        
        # Also try to find TTL in the text
        ttl_patterns = [
            r'ttl[=\s:]*(\d+)',
            r'TTL[=\s:]*(\d+)',
        ]
        
        for pattern in ttl_patterns:
            match = re.search(pattern, service_details, re.IGNORECASE)
            if match:
                try:
                    return int(match.group(1))
                except ValueError:
                    continue
        
        return None

def generate_netscan_markdown(netscan_data, output_dir):
    """Generate NETSCAN markdown report"""
    content = ["# NETSCAN Report", ""]
    
    if not netscan_data:
        content.append("No NETSCAN data available.")
    else:
        for ip, data in netscan_data.items():
            ttl = data.get('ttl', 'Unknown')
            os_type = data.get('os', 'Unknown')
            content.append(f"[+] {ip} (ttl={ttl}, OS={os_type}):")
            
            services = data.get('services', [])
            if services:
                for plugin, context in services:
                    content.append(f"    [{plugin}] {context}")
            else:
                content.append("    No services found")
            content.append("")
    
    output_path = os.path.join(output_dir, "netscan.md")
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(content))
    info("NETSCAN Markdown report generated: {bgreen}{output_path}{rst}")


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