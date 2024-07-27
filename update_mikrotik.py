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

def execute_command(api, command, resource, **kwargs):
    try:
        api.get_resource(resource).add(**kwargs)
        print(f"Executed command: {command}")
    except Exception as e:
        print(f"Failed to execute command: {command}, Error: {e}")

def remove_items(api, resource, **kwargs):
    try:
        res = api.get_resource(resource)
        items = res.get(**kwargs)
        for item in items:
            res.remove(id=item['.id'])
            print(f"Removed item: {item['.id']} from {resource}")
    except Exception as e:
        print(f"Failed to remove items from {resource}, Error: {e}")

def is_valid_ip(ip):
    try:
        ipaddress.ip_network(ip, strict=False)
        return True
    except ValueError:
        return False
def block_ips_on_mikrotik(name, ips, speed_limit=None):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()
        address_list_name = f"blocked_{name.lower()}"
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        print(f"Valid IPs count: {len(valid_ips)}")
        for ip in valid_ips:
            execute_command(api, f"/ip/firewall/address-list/add =address={ip} =list={address_list_name}",
                            '/ip/firewall/address-list', address=ip, list=address_list_name)

        if speed_limit:
            for ip in valid_ips:
                execute_command(api, f"/queue/simple/add =name=limit_{name.lower()}_{ip} =target={ip} =max-limit={speed_limit}",
                                '/queue/simple', name=f"limit_{name.lower()}_{ip}", target=ip, max_limit=speed_limit)

        # Get the first rule ID to place our rule before it
        raw_rules = api.get_resource('/ip/firewall/raw').get()
        if raw_rules:
            first_rule_id = raw_rules[0]['.id']
            execute_command(api, f"/ip/firewall/raw/add =chain=prerouting =action=drop =src-address-list={address_list_name} =comment=Drop traffic from {address_list_name} =place-before={first_rule_id}",
                            '/ip/firewall/raw', chain='prerouting', action='drop', src_address_list=address_list_name, comment=f"Drop traffic from {address_list_name}", **{'place-before': first_rule_id})
        else:
            execute_command(api, f"/ip/firewall/raw/add =chain=prerouting =action=drop =src-address-list={address_list_name} =comment=Drop traffic from {address_list_name}",
                            '/ip/firewall/raw', chain='prerouting', action='drop', src_address_list=address_list_name, comment=f"Drop traffic from {address_list_name}")

        print(f"Successfully added {len(valid_ips)} IPs to the Mikrotik address list and set speed limit.")
        api_pool.disconnect()
    except Exception as e:
        print(f"Failed to add IPs to Mikrotik: {e}")

def remove_ips_from_mikrotik(name):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()
        address_list_name = f"blocked_{name.lower()}"
        remove_items(api, '/ip/firewall/address-list', list=address_list_name)
        remove_items(api, '/ip/firewall/raw', comment=f"Drop traffic from {address_list_name}")
        remove_items(api, '/queue/simple', name=f"limit_{name.lower()}")

        print(f"Successfully removed all IPs and rules for {name} from the Mikrotik.")
        api_pool.disconnect()
    except Exception as e:
        print(f"Failed to remove IPs from Mikrotik: {e}")

def add_ips_to_list(list_name, ips):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()
        valid_ips = [ip for ip in ips if is_valid_ip(ip)]
        print(f"Valid IPs count: {len(valid_ips)}")
        for ip in valid_ips:
            execute_command(api, f"/ip/firewall/address-list/add =address={ip} =list={list_name}",
                            '/ip/firewall/address-list', address=ip, list=list_name)

        if list_name == "whitelist":
            for ip in valid_ips:
                execute_command(api, f"/ip/firewall/filter/add =chain=input =action=accept =src-address-list={list_name} =comment=Accept traffic from {list_name}",
                                '/ip/firewall/filter', chain='input', action='accept', src_address_list=list_name, comment=f"Accept traffic from {list_name}")

        print(f"Successfully added {len(valid_ips)} IPs to the Mikrotik {list_name} list and created firewall rules.")
        api_pool.disconnect()
    except Exception as e:
        print(f"Failed to add IPs to Mikrotik {list_name} list: {e}")

def remove_ips_from_list(list_name, ips):
    try:
        api_pool = RouterOsApiPool(router_ip, username=router_username, password=router_password, plaintext_login=True)
        api = api_pool.get_api()
        for ip in ips:
            if is_valid_ip(ip):
                remove_items(api, '/ip/firewall/address-list', address=ip, list=list_name)
        if list_name == "whitelist":
            remove_items(api, '/ip/firewall/filter', comment=f"Accept traffic from {list_name}", src_address_list=list_name)
        print(f"Successfully removed IPs and rules from the Mikrotik {list_name} list.")
        api_pool.disconnect()
    except Exception as e:
        print(f"Failed to remove IPs from Mikrotik {list_name} list: {e}")
def main(force_update=False, remove_country=None, remove_asn=None, add_whitelist=None, add_blocklist=None, remove_whitelist=None, remove_blocklist=None):
    data = load_data()
    print("Loaded data from file:")
    print(json.dumps(data, indent=4))

    if remove_country:
        remove_ips_from_mikrotik(remove_country)
    
    if remove_asn:
        remove_ips_from_mikrotik(remove_asn)

    if add_whitelist:
        add_ips_to_list("whitelist", [add_whitelist])
    
    if add_blocklist:
        add_ips_to_list("blocklist", [add_blocklist])

    if remove_whitelist:
        remove_ips_from_list("whitelist", [remove_whitelist])

    if remove_blocklist:
        remove_ips_from_list("blocklist", [remove_blocklist])

    if force_update or should_update(data):
        print("Updating IP data...")
        for country in data['blocked_countries']:
            ips = get_cidr_ips_from_github(country)
            print(f"Fetched {len(ips)} IPs for {country}")
            speed_limit = next((setting['setting_value'] for setting in data['settings'] if setting['setting_name'] == f"speed_limit_{country.lower()}"), None)
            block_ips_on_mikrotik(country, ips, speed_limit)
        
        for asn in data['blocked_asns']:
            ips = get_ips_from_asn(asn)
            print(f"Fetched {len(ips)} IPs for ASN {asn}")
            speed_limit = next((setting['setting_value'] for setting in data['settings'] if setting['setting_name'] == f"speed_limit_asn_{asn}"), None)
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
