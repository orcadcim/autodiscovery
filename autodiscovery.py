from ipaddress import IPv4Network
import argparse
import netifaces
import nmap
import requests


def create_parser():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        '-e', '--email',
        dest='email',
        metavar='',
        help='Your Orca DCIM email',
        required=True,
    )
    parser.add_argument(
        '-p', '--password',
        dest='password',
        metavar='',
        help='Your Orca DCIM password',
        required=True,
    )
    parser.add_argument(
        '-t', '--tenant',
        dest='tenant',
        metavar='',
        help='Your Orca DCIM tenant name',
        required=True,
    )
    return parser.parse_args()

def main():
    args = create_parser()

    # Find this server's interfaces
    interfaces = []
    print("Interface addresses found on this server:")
    for interface in netifaces.interfaces():
        interfaces.append(netifaces.ifaddresses(interface)[netifaces.AF_INET])
        for address in netifaces.ifaddresses(interface)[netifaces.AF_INET]:
            print(address['addr'], address['netmask'])

    all_hosts = []
    data = {}
    nm = nmap.PortScanner()
    # Use each interface's IP address to find the local network address.
    # Then, scan the network for responsive hosts.
    for interface in interfaces:
        for address in interface:
            # Find the network address based on the interface's IP address and netmask
            network_address = str(
                IPv4Network("{}/{}".format(
                    address['addr'],
                    address['netmask'],
                ), strict=False)
            )
            hosts = []
            if '127.0.0.0' not in network_address:
                scan = False
                while not scan == 'y' and not scan == 'n':
                    scan = input(f"Scan {network_address}? (Y/n) ").lower().strip()
                    if scan == '':
                        scan = 'y'
                if scan == 'y':
                    print(f"Scanning {network_address}...")
                    # Use nmap to ping sweep the network for "up" hosts
                    nm.scan(hosts=network_address, arguments='-sn -PE')
                    for host in nm.all_hosts():
                        if nm[host]['status']['state'] == 'up':
                            hosts.append({
                                'ip_address': host,
                                'hostnames': nm[host]['hostnames'],
                            })
                    if hosts:
                        data[network_address] = {
                            'is_aggregate': True,
                            'hostnames': None
                        }
                        for host in hosts:
                            data[host['ip_address']] = {
                                'is_aggregate': False,
                                'hostnames': host['hostnames']
                            }
                else:
                    continue
    for address, options in data.items():
        device_pk = None
        if options['hostnames']:
            # Create these devices
            for hostname in options['hostnames']:
                if not hostname['name'] == '':
                    post_data = {
                        'name': hostname['name'],
                        'rack_height': 1
                    }
                    r = requests.post(
                        f'https://{args.tenant}.orcadcim.com/api/devices/',
                        auth=(f'{args.email}', f'{args.password}'),
                        data=post_data
                    )
                    device_pk = r.json()['id']
                    print(f"HTTP status: {r.status_code}; Device: {r.json()['name']}; ID: {r.json()['id']}")
        # Create the prefixes
        post_data = {
            'name': address,
            'ip_address': address,
            'is_aggregate': options['is_aggregate']
        }
        if device_pk:
            post_data['device'] = device_pk
        r = requests.post(
            f'https://{args.tenant}.orcadcim.com/api/prefixes/',
            auth=(f'{args.email}', f'{args.password}'),
            data=post_data
        )
        print(f"HTTP status: {r.status_code}; Prefix: {r.json()['ip_address']}; ID: {r.json()['id']}")

if __name__ == "__main__":
    main()
