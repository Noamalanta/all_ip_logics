import aiohttp
import asyncio
import json
import re

SHODAN_API_KEY = 'ZTjGPNFY44ht9i32lhBzHUfyI5kZYejk'

CLOUD_REGEX = re.compile(r"(cloud|cdn)", re.IGNORECASE)
VPN_REGEX = re.compile(r"vpn", re.IGNORECASE)

async def get_shodan_data_for_ip(session, ip, results, cloud_results):
    """Retrieve data for a single IP address from Shodan asynchronously."""
    url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
    try:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.json()

                # Extract data with default empty string for None
                extracted_data = {
                    "city": data.get("city", ""),
                    "region_code": data.get("region_code", ""),
                    "os": data.get("os", ""),
                    "tags": data.get("tags", []),
                    "isp": data.get("isp", ""),  # Ensure default to empty string if None
                    "ports": data.get("ports", []),
                    "hostnames": data.get("hostnames", []),
                    "country_code": data.get("country_code", ""),
                    "domains": data.get("domains", []),
                    "org": data.get("org", ""),
                    "asn": data.get("asn", ""),
                    "portscan": [],
                }

                # Ensure isp, tags, and domains are always treated as strings
                isp = str(extracted_data.get("isp", ""))
                if any(CLOUD_REGEX.search(tag) for tag in extracted_data["tags"]) or \
                   CLOUD_REGEX.search(isp) or \
                   any(CLOUD_REGEX.search(str(domain)) for domain in extracted_data.get("domains", [])):  # Ensure domains are strings
                    print(f"Cloud or CDN detected in {ip}, storing in cloud results.")
                    cloud_results[ip] = extracted_data
                    return

                # Extract data for each port
                for port_data in data.get("data", []):
                    http_data = port_data.get("http", {})

                    port_info = {
                        "port": port_data["port"],
                        "http": {
                            "status": http_data.get("status", ""),
                            "title": http_data.get("title", ""),
                            "waf": http_data.get("waf", ""),
                            "robots": http_data.get("robots", ""),
                            "redirects": http_data.get("redirects", ""),
                            "securitytxt": http_data.get("securitytxt", ""),
                            "sitemap_hash": http_data.get("sitemap_hash", ""),
                            "dom_hash": http_data.get("dom_hash", ""),
                            "headers_hash": http_data.get("headers_hash", ""),
                            "host": http_data.get("host", "")
                        },
                        "product": port_data.get("product", ""),
                        "cloud": port_data.get("cloud", {}),
                        "tags": port_data.get("tags", []),
                        "hostnames": port_data.get("hostnames", []),
                        "vulns": port_data.get("vulns", []),
                        "jarm": port_data.get("jarm", ""),
                        "cert": port_data.get("ssl", {}).get("cert", {}),
                        "ja3s": port_data.get("ssl", {}).get("ja3s", "")
                    }
                    extracted_data["portscan"].append(port_info)

                # Prioritize IP if hostname or domain contains "vpn"
                if any(VPN_REGEX.search(hostname) for hostname in extracted_data.get("hostnames", [])) or \
                   any(VPN_REGEX.search(str(domain)) for domain in extracted_data.get("domains", [])):  # Ensure domains are strings
                    # If "vpn" is found, prioritize this IP in the result
                    results[ip] = extracted_data
                    print(f"VPN detected in {ip}, prioritizing in results.")
                else:
                    results[ip] = extracted_data
                    print(f"Processed data for IP {ip}: {extracted_data}")

            elif response.status == 429:
                print(f"Rate limit hit for {ip}. Retrying in 60 seconds...")
                await asyncio.sleep(60)  # Delay to prevent rate limiting
                return await get_shodan_data_for_ip(session, ip, results, cloud_results)
            else:
                print(f"Failed to get data for {ip}, Status Code: {response.status}")
    except aiohttp.ClientError as e:
        print(f"Error occurred while sending request to {url}: {e}")



async def fetch_shodan_data(ips_data):
    async with aiohttp.ClientSession() as session:
        results = {}
        cloud_results = {}
        tasks = []
        
        # Iterate directly through the list of IPs
        for ip in ips_data:  # No need to access it as ips_data["ips"]
            tasks.append(get_shodan_data_for_ip(session, ip, results, cloud_results))
        
        # Wait for all tasks to complete
        await asyncio.gather(*tasks)
        
        return results, cloud_results

def read_ips_from_file(file_path):
    """Read the IPs from a text file (one IP per line)."""
    try:
        with open(file_path, 'r') as f:
            # Read each line, strip newline characters, and filter out any empty lines
            ips_data = [line.strip() for line in f.readlines() if line.strip()]
        return ips_data
    except FileNotFoundError:
        print(f"File {file_path} not found.")
        return None
    except Exception as e:
        print(f"Error reading the file {file_path}: {e}")
        return None

    
def write_results_to_file(results, output_file):
    """Write the results to a JSON file."""
    try:
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"Results successfully written to {output_file}")
    except Exception as e:
        print(f"Error writing results to file: {e}")

def main():
    file_path = r"C:\Users\NoamYitzhack\Documents\python projects\Create_DBs\ip_logics\geenergies_ips.txt"  
    output_file = "shodan_results_genergies.json" 
    cloud_output_file = "cloud_scan_geenergies.json"  

    ips_data = read_ips_from_file(file_path)
    
    if ips_data is None:
        print("Failed to load IPs data.")
        return

    # Run the asyncio event loop to fetch the data
    results, cloud_results = asyncio.run(fetch_shodan_data(ips_data))
    
    # Write the results to a JSON file
    write_results_to_file(results, output_file)
    
    # Write cloud results to a separate JSON file
    write_results_to_file(cloud_results, cloud_output_file)

if __name__ == "__main__":
    main()
