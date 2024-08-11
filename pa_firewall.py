import argparse  # for command line arguments
import getpass  # for secure password input
import requests  # to make HTTP requests
from defusedxml.ElementTree import ElementTree  # to parse securely XML responses
from colorama import Style, Fore  # for colorized output
from cryptography.fernet import Fernet  # for encryption

# Generate a key for encryption
encryption_key = Fernet.generate_key()
cipher_suite = Fernet(encryption_key)

def generate_apikey(user, ip):
    admin_password = getpass.getpass("Enter the password: ")

    # Make the API request to generate the key
    url = f'https://{ip}/api/?type=keygen&user={user}&password={admin_password}'
    response = requests.get(url, verify=False)  # verify=False to ignore SSL warnings

    # Parse the XML response to extract the API key
    tree = ElementTree(ET.fromstring(response.content))
    root = tree.getroot()

    # Extract API key
    api_key = root.find(".//key").text

    print(f"{Fore.GREEN}[+]{Style.RESET_ALL} API Key generated successfully: {api_key}")
    return api_key

def save_api_key_encrypted(api_key, filename="apikey.key", keyfile="encryption.key"):
    # Encrypt the API key
    encrypted_key = cipher_suite.encrypt(api_key.encode())

    # Save the encrypted key and the encryption key to files
    with open(filename, 'wb') as file:
        file.write(encrypted_key)

    with open(keyfile, 'wb') as file:
        file.write(encryption_key)

    print(f"{Fore.GREEN}API Key encrypted and saved to {filename}{Style.RESET_ALL}")

def load_api_key_encrypted(filename="apikey.key", keyfile="encryption.key"):
    # Load the encryption key
    with open(keyfile, 'rb') as file:
        loaded_key = file.read()

    loaded_cipher_suite = Fernet(loaded_key)

    # Load and decrypt the API key
    with open(filename, 'rb') as file:
        encrypted_key = file.read()

    decrypted_key = loaded_cipher_suite.decrypt(encrypted_key)
    return decrypted_key.decode()

def check_api_connection(ip, api_key):
    url = f"https://{ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={api_key}"
    response = requests.get(url, verify=False)

    # Parse the XML response to extract the API key
    tree = ElementTree(ET.fromstring(response.content))
    root = tree.getroot()

    status = root.attrib.get("status", "unknown")
    hostname = root.find(".//hostname").text
    ip_address = root.find(".//ip-address").text

    print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Checking API connection\n")
    print(f"status = \"{status}\"")
    print(f"hostname = \"{hostname}\"")
    print(f"ip-address = \"{ip_address}\"")

    return status == "success"

def get_firewall_status(ip, api_key):
    url = f"https://{ip}/api/?type=op&cmd=<show><system><info></info></system></show>&key={api_key}"
    response = requests.get(url, verify=False)

    # Parse the XML response to extract the API key
    tree = ElementTree(ET.fromstring(response.content))
    root = tree.getroot()

    status = root.attrib.get("status", "unknown")
    hostname = root.find(".//hostname").text
    ip_address = root.find(".//ip-address").text
    netmask = root.find(".//netmask").text
    default_gateway = root.find(".//default-gateway").text
    uptime = root.find(".//uptime").text
    serial = root.find(".//serial").text
    sw_version = root.find(".//sw-version").text
    av_version = root.find(".//av-version").text
    threat_version = root.find(".//threat-version").text
    wildfire_version = root.find(".//wildfire-version").text
    operational_mode = root.find(".//operational-mode").text

    print(f"Status = \"{status}\"")
    print(f"hostname = \"{hostname}\"")
    print(f"ip-address = \"{ip_address}\"")
    print(f"netmask = \"{netmask}\"")
    print(f"default-gateway = \"{default_gateway}\"")
    print(f"uptime = \"{uptime}\"")
    print(f"serial = \"{serial}\"")
    print(f"sw-version = \"{sw_version}\"")
    print(f"av-version = \"{av_version}\"")
    print(f"threat-version = \"{threat_version}\"")
    print(f"wildfire-version = \"{wildfire-version}\"")
    print(f"operational-mode = \"{operational_mode}\"")
    print()  # Blank line for separation

def process_ip_file(file_path):
    with open(file_path, 'r') as file:
        return [line.strip() for line in file if line.strip()]

def main():
    parser = argparse.ArgumentParser(description='Palo Alto Enumeration Tool')
    parser.add_argument('-ip', nargs='+', help='Defines one or more IP addresses of the target firewalls.')
    parser.add_argument('-ip-file', help='Specifies a file containing IP addresses of target firewalls.')
    parser.add_argument('-generate_api', action='store_true', help='Switch parameter to generate an API key')
    parser.add_argument('-check-status', action='store_true', help='Check the status of the firewalls.')

    args = parser.parse_args()

    # Process IP addresses
    ip_addresses = []
    if args.ip:
        ip_addresses.extend(args.ip)
    if args.ip_file:
        ip_addresses.extend(process_ip_file(args.ip_file))

    if not ip_addresses:
        print(f"{Fore.RED}[x]{Style.RESET_ALL} No IP addresses provided!")
        return

    if args.generate_api:
        if not ip_addresses:
            print(f"{Fore.RED}[x]{Style.RESET_ALL} -ip or -ip-file is required when generating an API key!")
            return

        user = input("Enter the username: ")
        for ip in ip_addresses:
            api_key = generate_apikey(user, ip)
            save_api_key_encrypted(api_key)

    elif args.check_status:
        api_key = load_api_key_encrypted()
        for ip in ip_addresses:
            print(f"{Fore.YELLOW}[INFO]{Style.RESET_ALL} Retrieving status for {ip}...")
            get_firewall_status(ip, api_key)

    else:
        api_key = load_api_key_encrypted()

        for ip in ip_addresses:
            # Check the API connection for each IP address
            if check_api_connection(ip, api_key):
                print(f"{Fore.GREEN}[+]{Style.RESET_ALL} API connection to {ip} successful!")
                # Continue with other API calls or operations
            else:
                print(f"{Fore.RED}[x]{Style.RESET_ALL} API connection to {ip} failed!")

if __name__ == "__main__":
    main()
