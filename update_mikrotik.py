import os
import json
import requests
from routeros_api import RouterOsApiPool
from dotenv import load_dotenv
from datetime import datetime, timedelta
import ipaddress

# .env dosyasındaki çevresel değişkenleri yükle
load_dotenv()

# Mikrotik Router bilgileri
router_ip = os.getenv("MIKROTIK_HOST")
router_username = os.getenv("MIKROTIK_USER")
router_password = os.getenv("MIKROTIK_PASSWORD")

# Veritabanı dosyası
data_file = '/app/data/data.json'

def load_data():
    if not os.path.exists(data_file):
        return {"blocked_countries": [], "blocked_asns": [], "settings": [], "last_update": "", "whitelist_ips": [], "blocked_ips": []}
    with open(data_file, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(data_file, 'w') as f:
        json.dump(data, f, indent=4)

def get_cidr_ips_from_github(country_code):
    url = f"https://raw.githubusercontent.com/herrbischoff/country-ip-blocks/master/ipv4/{country_code.lower()}.cidr"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Successfully fetched CIDR data for {country_code}")
        return response.text.splitlines()
    else:
        print(f"Failed to fetch CIDR data for {country_code}: {response.status_code}")
        return []

def get_ips_from_asn(asn):
    url = f"https://api.hackertarget.com/aslookup/?q=AS{asn}"
    response = requests.get(url)
    if response.status_code == 200:
        print(f"Successfully fetched IP data for ASN {asn}")
        return response.text.splitlines()
    else:
        print(f"Failed to fetch IP data for ASN {asn}: {response.status_code}")
        return []
def should_update(data):
    if "last_update" not in data:
        return True
    last_update = datetime.strptime(data["last_update"], "%Y-%m-%d")
    return datetime.now() > last_update + timedelta(days=30)

def block_ips_on_mikrotik(name, ips, speed_limit=None):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()

        address_list_name = f"blocked_{name.lower()}"
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        print(f"Valid IPs count: {len(valid_ips)}")
        for ip in valid_ips:
            command = f"/ip/firewall/address-list/add =address={ip} =list={address_list_name}"
            print(f"Executing command: {command}")
            api.get_resource('/ip/firewall/address-list').add(
                address=ip,
                list=address_list_name
            )
            print(f"Added IP {ip} to the Mikrotik address list {address_list_name}")

        if speed_limit:
            for ip in valid_ips:
                command = f"/queue/simple/add =name=limit_{name.lower()}_{ip} =target={ip} =max-limit={speed_limit}"
                print(f"Executing command: {command}")
                api.get_resource('/queue/simple').add(
                    name=f"limit_{name.lower()}_{ip}",
                    target=ip,
                    max_limit=speed_limit
                )
                print(f"Set speed limit {speed_limit} for {ip}")

        # Firewall rule to drop traffic from this address list
        command = f"/ip/firewall/raw/add =chain=prerouting =action=drop =src-address-list={address_list_name} =comment=Drop traffic from {address_list_name}"
        print(f"Executing command: {command}")
        api.get_resource('/ip/firewall/raw').add(
            chain='prerouting',
            action='drop',
            src_address_list=address_list_name,
            comment=f"Drop traffic from {address_list_name}"
        )
        print(f"Created raw rule to drop traffic from {address_list_name}")

        api_pool.disconnect()
        print(f"Successfully added {len(valid_ips)} IPs to the Mikrotik address list and set speed limit.")
    except Exception as e:
        print(f"Failed to add IPs to Mikrotik: {e}")

def remove_ips_from_mikrotik(name):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()

        address_list_name = f"blocked_{name.lower()}"
        
        # Remove all IPs from the address list
        address_list_resource = api.get_resource('/ip/firewall/address-list')
        addresses = address_list_resource.get(list=address_list_name)
        for address in addresses:
            address_list_resource.remove(id=address['.id'])
            print(f"Removed IP {address['address']} from the Mikrotik address list {address_list_name}")
        
        # Remove raw rule
        firewall_raw_resource = api.get_resource('/ip/firewall/raw')
        rules = firewall_raw_resource.get(comment=f"Drop traffic from {address_list_name}")
        for rule in rules:
            firewall_raw_resource.remove(id=rule['.id'])
            print(f"Removed raw rule for {address_list_name}")

        # Remove speed limit rule if exists
        queue_simple_resource = api.get_resource('/queue/simple')
        queues = queue_simple_resource.get(name=f"limit_{name.lower()}")
        for queue in queues:
            queue_simple_resource.remove(id=queue['.id'])
            print(f"Removed speed limit rule for {address_list_name}")

        api_pool.disconnect()
        print(f"Successfully removed all IPs and rules for {name} from the Mikrotik.")
    except Exception as e:
        print(f"Failed to remove IPs from Mikrotik: {e}")
def is_valid_ip(ip):
    try:
        # Check if IP is valid or if it's a valid CIDR notation
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False

def add_ips_to_whitelist(ips):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()

        address_list_name = "whitelist"
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        print(f"Valid IPs count: {len(valid_ips)}")
        for ip in valid_ips:
            try:
                api.get_resource('/ip/firewall/address-list').add(
                    address=ip,
                    list=address_list_name
                )
                print(f"Added IP {ip} to the Mikrotik whitelist")
            except Exception as e:
                if "already have such entry" in str(e):
                    print(f"IP {ip} already exists in the whitelist, skipping.")
                else:
                    print(f"Failed to add IP {ip} to Mikrotik whitelist: {e}")

        try:
            for ip in valid_ips:
                api.get_resource('/ip/firewall/filter').add(
                    chain='input',
                    action='accept',
                    src_address_list=address_list_name,
                    comment=f"Accept traffic from {address_list_name}"
                )
                print(f"Created firewall rule to accept traffic from {address_list_name}")

        except Exception as e:
            if "already have such entry" in str(e):
                print(f"Firewall rule for {address_list_name} already exists, skipping.")
            else:
                print(f"Failed to create firewall rule for {address_list_name}: {e}")

        api_pool.disconnect()
        print(f"Successfully added {len(valid_ips)} IPs to the Mikrotik whitelist and created firewall rules.")
    except Exception as e:
        print(f"Failed to add IPs to Mikrotik whitelist: {e}")

def remove_ips_from_whitelist(ips):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()

        address_list_name = "whitelist"
        
        address_list_resource = api.get_resource('/ip/firewall/address-list')
        for ip in ips:
            if is_valid_ip(ip):
                addresses = address_list_resource.get(address=ip, list=address_list_name)
                for address in addresses:
                    address_list_resource.remove(id=address['.id'])
                    print(f"Removed IP {address['address']} from the Mikrotik whitelist")
        
        firewall_filter_resource = api.get_resource('/ip/firewall/filter')
        rules = firewall_filter_resource.get(comment=f"Accept traffic from {address_list_name}", src_address_list=address_list_name)
        for rule in rules:
            firewall_filter_resource.remove(id=rule['.id'])
            print(f"Removed firewall rule for {address_list_name}")

        api_pool.disconnect()
        print(f"Successfully removed IPs and rules from the Mikrotik whitelist.")
    except Exception as e:
        print(f"Failed to remove IPs from Mikrotik whitelist: {e}")

def add_ips_to_blocklist(ips):
    block_ips_on_mikrotik("blocklist", ips)

def remove_ips_from_blocklist(ips):
    for ip in ips:
        remove_ip_from_mikrotik("blocklist", ip)
def main(force_update=False, remove_country=None, remove_asn=None, add_whitelist=None, add_blocklist=None, remove_whitelist=None, remove_blocklist=None):
    data = load_data()
    print("Loaded data from file:")
    print(json.dumps(data, indent=4))

    if remove_country:
        remove_ips_from_mikrotik(remove_country)
    
    if remove_asn:
        remove_ips_from_mikrotik(remove_asn)

    if add_whitelist:
        add_ips_to_whitelist([add_whitelist])
    
    if add_blocklist:
        add_ips_to_blocklist([add_blocklist])

    if remove_whitelist:
        remove_ips_from_whitelist([remove_whitelist])

    if remove_blocklist:
        remove_ips_from_blocklist([remove_blocklist])

    if force_update or should_update(data):
        print("Updating IP data...")
        for country in data['blocked_countries']:
            ips = get_cidr_ips_from_github(country)
            print(f"Fetched {len(ips)} IPs for {country}")
            speed_limit = None
            for setting in data['settings']:
                if setting['setting_name'] == f"speed_limit_{country.lower()}":
                    speed_limit = setting['setting_value']
                    break
            block_ips_on_mikrotik(country, ips, speed_limit)
        
        for asn in data['blocked_asns']:
            ips = get_ips_from_asn(asn)
            print(f"Fetched {len(ips)} IPs for ASN {asn}")
            speed_limit = None
            for setting in data['settings']:
                if setting['setting_name'] == f"speed_limit_asn_{asn}":
                    speed_limit = setting['setting_value']
                    break
            block_ips_on_mikrotik(asn, ips, speed_limit)
        
        save_data({
            **data,
            "last_update": datetime.now().strftime("%Y-%m-%d")
        })
        print("Saved updated data to file")
    else:
        print("IP data is up to date, no need to update.")

if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        if sys.argv[1] == '--remove_country':
            main(remove_country=sys.argv[2])
        elif sys.argv[1] == '--remove_asn':
            main(remove_asn=sys.argv[2])
        elif sys.argv[1] == '--add_whitelist':
            main(add_whitelist=sys.argv[2])
        elif sys.argv[1] == '--add_blocklist':
            main(add_blocklist=sys.argv[2])
        elif sys.argv[1] == '--remove_whitelist':
            main(remove_whitelist=sys.argv[2])
        elif sys.argv[1] == '--remove_blocklist':
            main(remove_blocklist=sys.argv[2])
        else:
            main(force_update=True)
    else:
        main(force_update=True)
