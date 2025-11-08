"""Common utility functions for Bit00 framework."""
import ipaddress
import tldextract
import time
from typing import List
from ipaddress import ip_address, ip_network, summarize_address_range, ip_interface

# =============================================================================
# VALIDATED TARGETS IF IPADDRESS, CIDR OR HOSTNAME
# =============================================================================

def is_domain(domain: str) -> bool:
    """Check if string is valid domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid domain, False otherwise
    """
    try:
        _domain = tldextract.extract(domain)
        if _domain.domain and _domain.suffix:
            return True
    except Exception:
        return False

def is_valid_ip(ip: str) -> bool:
    """Check if string is valid IP address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid IP, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
        
def is_valid_target(target: str) -> bool:
    """Check if string is valid target (domain or IP).
    
    Args:
        target: Target to validate
        
    Returns:
        True if valid target, False otherwise
    """
    return is_domain(target) or is_valid_ip(target)

def expand_cidr(cidr: str) -> List[str]:
    """Expand CIDR notation into list of IPs.
    
    Args:
        cidr: CIDR range (e.g. 192.168.1.0/24)
        
    Returns:
        List of IP addresses
        
    Raises:
        ValueError: If invalid CIDR format
    """
    try:
        network = ipaddress.ip_network(cidr)
        return [str(ip) for ip in network.hosts()]
    except ValueError as e:
        raise ValueError(f"Invalid CIDR format: {str(e)}")


# =============================================================================
# EXTRACT BASEDOMAIN AND FQDN
# =============================================================================

_extract = tldextract.TLDExtract()
@staticmethod
def extract_base_domain(url):
    return str(_extract(url).domain + '.' + _extract(url).suffix)

@staticmethod
def extract_fqdn(subdomain):
    return _extract(subdomain).fqdn


# =============================================================================
# PARSE TARGETS ON ARGS MENU
# =============================================================================

def parse_targets(target: str) -> List[str]:
    """Parse target string into list of targets.
    
    Supports:
    - Single IP: 192.168.1.1
    - CIDR: 192.168.1.0/24
    - IP Range: 192.168.1.1-192.168.1.10 or 192.168.1.1-10
    - Domain: example.com
    - IPv6: 2001:db8::1
    
    Args:
        target: Target specification
        
    Returns:
        List of expanded targets
    """
    targets = []
    target = target.strip()
    
    try:
        # Handle IP range with hyphen
        if "-" in target:
            start_ip, end_ip = target.split("-")
            try:
                # Full IP for end range
                end_ip = ip_address(end_ip)
            except ValueError:
                # Short notation (e.g. 192.168.1.1-10)
                first_three_octets = start_ip.split(".")[:-1]
                first_three_octets.append(end_ip)
                end_ip = ip_address(".".join(first_three_octets))
            
            for ip_range in summarize_address_range(ip_address(start_ip), end_ip):
                targets.extend(str(ip) for ip in ip_range)
                
        # Handle CIDR and single IPs
        else:
            try:
                # IPv6 link-local addresses
                if ip_interface(target).ip.version == 6 and ip_address(target).is_link_local:
                    targets.append(str(target))
                else:
                    # CIDR or single IP
                    network = ip_network(target, strict=False)
                    targets.extend(str(ip) for ip in network)
            except ValueError:
                # If not an IP/CIDR, treat as domain
                if is_domain(target):
                    targets.append(target)
                else:
                    raise ValueError(f"Invalid target format: {target}")
                    
    except Exception as e:
        raise ValueError(f"Failed to parse target '{target}': {str(e)}")
        
    return targets


# =============================================================================
# CALCULATE TIME
# =============================================================================

def calculate_elapsed_time(start_time):
    elapsed_seconds = round(time.time() - start_time)
    m, s = divmod(elapsed_seconds, 60)
    h, m = divmod(m, 60)

    elapsed_time = []
    if h == 1:
        elapsed_time.append(str(h) + ' hour')
    elif h > 1:
        elapsed_time.append(str(h) + ' hours')
    if m == 1:
        elapsed_time.append(str(m) + ' minute')
    elif m > 1:
        elapsed_time.append(str(m) + ' minutes')
    if s == 1:
        elapsed_time.append(str(s) + ' second')
    elif s > 1:
        elapsed_time.append(str(s) + ' seconds')
    else:
        elapsed_time.append('less than a second')
    return ', '.join(elapsed_time)  



