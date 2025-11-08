import re
import json
import xml.etree.ElementTree as ET
from collections import defaultdict
from datetime import datetime

def detect_os_from_ttl(ttl):
    """
    Detect operating system based on TTL value
    TTL < 64: Linux/Unix
    TTL >= 64: Windows
    """
    try:
        ttl_value = int(ttl)
        if ttl_value < 64:
            return "Linux"
        else:
            return "Windows"
    except (ValueError, TypeError):
        return "Unknown"

def parse_log_file(log_content):
    """
    Parse the log file and extract structured data
    """
    hosts = defaultdict(lambda: {
        'ttl': None,
        'os': 'Unknown',
        'plugins': defaultdict(dict)
    })
    
    lines = log_content.strip().split('\n')
    
    for line in lines:
        # Extract basic components
        timestamp_match = re.search(r'\[(\d+:\d+\.\d+\.\d+)\]', line)
        event_type_match = re.search(r':(\w+):', line)
        plugin_match = re.search(r':([^:]+):([^:]+):', line)
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', line)
        
        if not all([timestamp_match, event_type_match, plugin_match, ip_match]):
            continue
            
        event_type = event_type_match.group(1)
        plugin = plugin_match.group(1)
        ip = ip_match.group(1)
        
        # Extract TTL (always at the end of the line)
        ttl_match = re.search(r'(\d+)$', line)
        if ttl_match:
            ttl_value = ttl_match.group(1)
            hosts[ip]['ttl'] = ttl_value
            hosts[ip]['os'] = detect_os_from_ttl(ttl_value)
        
        # Handle portscan events
        if event_type == 'portscan':
            # Extract port/service information
            port_match = re.search(r':(tcp/\d+/[^:]+)-([^54]+)', line)
            if port_match:
                port_service = port_match.group(1)
                service_info = port_match.group(2).strip()
                hosts[ip]['plugins'][plugin][port_service] = service_info
        
        # Handle vulnerability events
        elif event_type in ['vuln', 'cve']:
            # Extract vulnerability information
            if 'tcp/' in line:
                port_match = re.search(r'(tcp/\d+/[^:]+):', line)
                if port_match:
                    port_service = port_match.group(1)
                    vuln_info = ""
                    
                    if 'VULNERABLE' in line:
                        vuln_info = "VULNERABLE"
                    if 'CVE-' in line:
                        cve_match = re.search(r'(CVE-\d+-\d+)', line)
                        if cve_match:
                            vuln_info += f" - {cve_match.group(1)}"
                    
                    # Add vulnerability to existing service or create new entry
                    if port_service in hosts[ip]['plugins']['NmapTCPTop1000']:
                        base_service = hosts[ip]['plugins']['NmapTCPTop1000'][port_service]
                        hosts[ip]['plugins'][plugin][port_service] = f"{base_service} {vuln_info}"
                    else:
                        hosts[ip]['plugins'][plugin][port_service] = vuln_info
    
    return dict(hosts)

def generate_markdown_report(hosts_data):
    """
    Generate Markdown format report with OS detection
    """
    markdown = "# NETSCAN REPORT:\n\n"
    
    for ip, data in hosts_data.items():
        markdown += f"[+] {ip} (ttl={data['ttl']}, OS={data['os']}):\n"
        
        for plugin, services in data['plugins'].items():
            for port_service, service_info in services.items():
                markdown += f"\t[{plugin}] {port_service}: {service_info}\n"
        
        markdown += "\n"
    
    return markdown

def generate_json_report(hosts_data):
    """
    Generate JSON format report with OS detection
    """
    json_data = {}
    
    for ip, data in hosts_data.items():
        json_data[ip] = {
            "OS": f"{data['os']} (ttl={data['ttl']})"
        }
        
        # Add plugins
        for plugin, services in data['plugins'].items():
            json_data[ip][plugin] = {}
            for port_service, service_info in services.items():
                json_data[ip][plugin][port_service] = service_info
    
    return json.dumps(json_data, indent=2)

def generate_xml_report(hosts_data):
    """
    Generate XML format report with OS detection
    """
    root = ET.Element("netscan_report")
    
    for ip, data in hosts_data.items():
        host_elem = ET.SubElement(root, "host", ip=ip)
        
        os_elem = ET.SubElement(host_elem, "OS")
        os_elem.text = f"{data['os']} (ttl={data['ttl']})"
        
        plugins_elem = ET.SubElement(host_elem, "plugins")
        
        for plugin, services in data['plugins'].items():
            plugin_elem = ET.SubElement(plugins_elem, plugin)
            
            for port_service, service_info in services.items():
                # Parse protocol/port/service
                parts = port_service.split('/')
                if len(parts) >= 3:
                    protocol = parts[0]
                    port = parts[1]
                    service_name = parts[2]
                    
                    service_elem = ET.SubElement(plugin_elem, "service", 
                                               protocol=protocol, 
                                               port=port, 
                                               name=service_name)
                    service_elem.text = service_info
    
    # Pretty print XML
    return ET.tostring(root, encoding='unicode', method='xml')

def generate_detailed_os_report(hosts_data):
    """
    Generate a separate detailed OS analysis report
    """
    report = "# OPERATING SYSTEM ANALYSIS REPORT\n\n"
    report += "## OS Detection based on TTL Values\n\n"
    report += "**Detection Rules:**\n"
    report += "- TTL < 64: Linux\n"
    report += "- TTL >= 64: Windows\n"
    report += "- Unable to parse TTL: Unknown\n\n"
    
    report += "## Host Analysis\n\n"
    
    linux_hosts = []
    windows_hosts = []
    unknown_hosts = []
    
    for ip, data in hosts_data.items():
        if data['os'] == 'Linux':
            linux_hosts.append((ip, data['ttl']))
        elif data['os'] == 'Windows':
            windows_hosts.append((ip, data['ttl']))
        else:
            unknown_hosts.append((ip, data['ttl']))
    
    report += "### Linux Hosts\n"
    if linux_hosts:
        for ip, ttl in linux_hosts:
            report += f"- {ip} (TTL: {ttl})\n"
    else:
        report += "- No Linux hosts detected\n"
    
    report += "\n### Windows Hosts\n"
    if windows_hosts:
        for ip, ttl in windows_hosts:
            report += f"- {ip} (TTL: {ttl})\n"
    else:
        report += "- No Windows hosts detected\n"
    
    report += "\n### Unknown OS Hosts\n"
    if unknown_hosts:
        for ip, ttl in unknown_hosts:
            report += f"- {ip} (TTL: {ttl})\n"
    else:
        report += "- No unknown OS hosts detected\n"
    
    report += f"\n## Summary\n"
    report += f"- Total hosts: {len(hosts_data)}\n"
    report += f"- Linux hosts: {len(linux_hosts)}\n"
    report += f"- Windows hosts: {len(windows_hosts)}\n"
    report += f"- Unknown OS: {len(unknown_hosts)}\n"
    
    return report

def save_reports(hosts_data, base_filename="netscan_report"):
    """
    Save all report formats to files
    """
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Generate reports
    markdown_report = generate_markdown_report(hosts_data)
    json_report = generate_json_report(hosts_data)
    xml_report = generate_xml_report(hosts_data)
    os_report = generate_detailed_os_report(hosts_data)
    
    # Save Main Markdown Report
    md_filename = f"{base_filename}_{timestamp}.md"
    with open(md_filename, 'w', encoding='utf-8') as f:
        f.write(markdown_report)
    print(f"Main Markdown report saved: {md_filename}")
    
    # Save OS Analysis Report
    os_filename = f"{base_filename}_os_analysis_{timestamp}.md"
    with open(os_filename, 'w', encoding='utf-8') as f:
        f.write(os_report)
    print(f"OS Analysis report saved: {os_filename}")
    
    # Save JSON
    json_filename = f"{base_filename}_{timestamp}.json"
    with open(json_filename, 'w', encoding='utf-8') as f:
        f.write(json_report)
    print(f"JSON report saved: {json_filename}")
    
    # Save XML
    xml_filename = f"{base_filename}_{timestamp}.xml"
    with open(xml_filename, 'w', encoding='utf-8') as f:
        f.write(xml_report)
    print(f"XML report saved: {xml_filename}")
    
    return md_filename, json_filename, xml_filename, os_filename

def print_os_summary(hosts_data):
    """
    Print a quick OS summary to console
    """
    print("\n" + "="*50)
    print("QUICK OS DETECTION SUMMARY")
    print("="*50)
    
    linux_count = 0
    windows_count = 0
    unknown_count = 0
    
    for ip, data in hosts_data.items():
        if data['os'] == 'Linux':
            linux_count += 1
        elif data['os'] == 'Windows':
            windows_count += 1
        else:
            unknown_count += 1
    
    print(f"Total hosts analyzed: {len(hosts_data)}")
    print(f"Linux hosts: {linux_count}")
    print(f"Windows hosts: {windows_count}")
    print(f"Unknown OS: {unknown_count}")
    print("="*50)

def main():
    """
    Main function to process the log file and generate reports
    """
    # Read the log file
    try:
        with open('patterns.log', 'r', encoding='utf-8') as f:
            log_content = f.read()
    except FileNotFoundError:
        print("Error: patterns.log file not found!")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return
    
    # Parse the log file
    print("Parsing log file...")
    hosts_data = parse_log_file(log_content)
    
    if not hosts_data:
        print("No data found in log file!")
        return
    
    print(f"Found {len(hosts_data)} hosts in the log file")
    
    # Print quick OS summary
    print_os_summary(hosts_data)
    
    # Generate and save reports
    print("\nGenerating reports...")
    md_file, json_file, xml_file, os_file = save_reports(hosts_data)
    
    print("\nReports generated successfully!")
    print(f"- Main Markdown: {md_file}")
    print(f"- OS Analysis: {os_file}")
    print(f"- JSON: {json_file}")
    print(f"- XML: {xml_file}")

# Alternative function to process log content directly
def process_log_content(log_content, base_filename="netscan_report"):
    """
    Process log content directly and generate reports
    """
    hosts_data = parse_log_file(log_content)
    
    if not hosts_data:
        print("No data found in log content!")
        return None
    
    print_os_summary(hosts_data)
    return save_reports(hosts_data, base_filename)

if __name__ == "__main__":
    main()