import os
import re
import socket
from urllib.parse import urlparse

class PACParser:
    def __init__(self, pac_file_path):
        """Initialize the PAC parser with the path to the PAC file."""
        self.pac_file_path = pac_file_path
        if not os.path.exists(pac_file_path):
            raise FileNotFoundError(f"PAC file not found at {pac_file_path}")
        
        # Read the PAC file
        with open(pac_file_path, 'r') as f:
            self.pac_content = f.read()

    def is_plain_hostname(self, hostname):
        """Check if the hostname is plain (no dots)."""
        return '.' not in hostname

    def dns_domain_is(self, hostname, domain):
        """Check if the hostname belongs to the specified domain."""
        return hostname.endswith(domain)

    def sh_exp_match(self, str, pattern):
        """Check if the string matches the shell pattern."""
        regex_pattern = pattern.replace('.', '\\.').replace('*', '.*').replace('?', '.')
        return bool(re.match(regex_pattern, str))

    def is_in_net(self, ip, subnet_ip, subnet_mask):
        """Check if the IP is in the specified subnet."""
        try:
            ip_int = int.from_bytes(socket.inet_aton(ip), byteorder='big')
            subnet_int = int.from_bytes(socket.inet_aton(subnet_ip), byteorder='big')
            mask_int = int.from_bytes(socket.inet_aton(subnet_mask), byteorder='big')
            return (ip_int & mask_int) == (subnet_int & mask_int)
        except:
            return False

    def my_ip_address(self):
        """Get the local machine's IP address."""
        try:
            # Create a socket connection to get the local IP
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"

    def dns_resolve(self, hostname):
        """Resolve a hostname to an IP address."""
        try:
            return socket.gethostbyname(hostname)
        except:
            return None

    def is_resolvable(self, hostname):
        """Check if a hostname can be resolved."""
        try:
            socket.gethostbyname(hostname)
            return True
        except:
            return False

    def dns_domain_levels(self, hostname):
        """Get the number of domain levels in the hostname."""
        return len(hostname.split('.')) - 1

    def local_host_or_domain_is(self, hostname, domain):
        """Check if the hostname is the local host or belongs to the specified domain."""
        if self.is_plain_hostname(hostname):
            return True
        return self.dns_domain_is(hostname, domain)

    def find_matching_proxy(self, url):
        """Find the matching proxy configuration for a given URL."""
        parsed_url = urlparse(url)
        hostname = parsed_url.netloc
        
        # Check if it's a plain hostname
        if self.is_plain_hostname(hostname):
            return {'type': 'DIRECT', 'condition': 'isPlainHostName', 'proxy': 'DIRECT'}
        
        # Check if it matches *.local
        if self.sh_exp_match(hostname, "*.local"):
            return {'type': 'DIRECT', 'condition': 'shExpMatch(*.local)', 'proxy': 'DIRECT'}
        
        # Check if it's in private IP ranges
        try:
            ip = self.dns_resolve(hostname)
            if ip:
                private_ranges = [
                    ("10.0.0.0", "255.0.0.0"),
                    ("172.16.0.0", "255.240.0.0"),
                    ("192.168.0.0", "255.255.0.0")
                ]
                for subnet_ip, subnet_mask in private_ranges:
                    if self.is_in_net(ip, subnet_ip, subnet_mask):
                        return {'type': 'DIRECT', 'condition': f'isInNet({ip}, {subnet_ip}, {subnet_mask})', 'proxy': 'DIRECT'}
        except:
            pass
        
        # If none of the above conditions match, use the default proxy
        return {'type': 'PROXY', 'condition': 'default', 'proxy': 'proxy.witness.ai:8080'}

def main():
    print("PAC File Parser")
    print("===============")
    
    # Get PAC file path
    while True:
        pac_file_path = input("\nEnter the path to your PAC file: ").strip()
        if os.path.exists(pac_file_path):
            break
        print("File not found. Please enter a valid path.")
    
    # Get URL to test
    url = input("Enter the URL to test: ").strip()
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    
    try:
        # Initialize parser
        parser = PACParser(pac_file_path)
        
        # Find matching proxy
        config = parser.find_matching_proxy(url)
        
        # Display results
        print("\nResults:")
        print("--------")
        print(f"URL: {url}")
        print(f"Hostname: {urlparse(url).netloc}")
        print(f"Proxy Type: {config['type']}")
        print(f"Proxy: {config['proxy']}")
        print(f"Matching Condition: {config['condition']}")
        
        # Additional information
        print("\nAdditional Information:")
        print("----------------------")
        print(f"Local IP Address: {parser.my_ip_address()}")
        print(f"DNS Resolution: {parser.dns_resolve(urlparse(url).netloc)}")
        print(f"Domain Levels: {parser.dns_domain_levels(urlparse(url).netloc)}")
        print(f"Is Resolvable: {parser.is_resolvable(urlparse(url).netloc)}")
        
    except Exception as e:
        print(f"\nError: {str(e)}")

if __name__ == "__main__":
    main()
