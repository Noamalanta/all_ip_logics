import dns.resolver

# Function to get A records for a given subdomain using specific nameservers
def get_ip(subdomain):
    try:
        # Create a custom resolver and set the nameservers (Google and Cloudflare)
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google's and Cloudflare's DNS servers
        
        # Perform A record query
        result = resolver.resolve(subdomain, 'A')
        return {ip.address for ip in result}  # Return as a set to ensure uniqueness
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN) as e:
        print(f"Error for {subdomain}: {e}")
        return set()
    except dns.resolver.NoNameservers as e:
        print(f"Nameserver error for {subdomain}: {e}")
        return set()

# Function to process the input file and get IP addresses
def process_subdomains(input_file, output_file):
    with open(input_file, 'r') as file:
        subdomains = file.readlines()
    
    # Use a set to store IPs (to ensure they are distinct)
    ip_addresses = set()
    
    for subdomain in subdomains:
        subdomain = subdomain.strip()  # Clean up any extra whitespace or newlines
        if subdomain:
            ips = get_ip(subdomain)
            ip_addresses.update(ips)  # Add all found IPs to the set

    # Write the distinct results to the output file
    with open(output_file, 'w') as file:
        for ip in ip_addresses:
            file.write(f"{ip}\n")

    print(f"Distinct IPs have been written to {output_file}")

# Example usage:
input_file = r"C:\Users\NoamYitzhack\Documents\re.txt"  
output_file = r"C:\Users\NoamYitzhack\Documents\python projects\Create_DBs\ip_logics\cyberarkcomips.txt"  # The output file where IPs will be saved

process_subdomains(input_file, output_file)
