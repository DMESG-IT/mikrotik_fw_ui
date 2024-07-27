from flask import Flask, request, redirect, render_template, session, url_for, flash
import json
import os
import subprocess
from datetime import datetime, timedelta
import base64

app = Flask(__name__)
app.secret_key = os.getenv("SECRET_KEY", "mysecretkey")

data_file = '/app/data/data.json'

# DDoS saldırılarının kaynağı olarak bilinen ve daha büyük nüfuslara sahip ülkeler
countries_list = [
    {"code": "CN", "name": "China"},
    {"code": "RU", "name": "Russia"},
    {"code": "US", "name": "United States"},
    {"code": "BR", "name": "Brazil"},
    {"code": "IN", "name": "India"},
    {"code": "ID", "name": "Indonesia"},
    {"code": "IR", "name": "Iran"},
    {"code": "VN", "name": "Vietnam"},
    {"code": "PK", "name": "Pakistan"},
    {"code": "TR", "name": "Turkey"},
    {"code": "UA", "name": "Ukraine"},
    {"code": "TH", "name": "Thailand"},
    {"code": "FR", "name": "France"},
    {"code": "GB", "name": "United Kingdom"},
    {"code": "DE", "name": "Germany"},
    {"code": "IT", "name": "Italy"},
    {"code": "JP", "name": "Japan"},
    {"code": "KR", "name": "South Korea"},
    {"code": "SA", "name": "Saudi Arabia"},
    {"code": "CA", "name": "Canada"},
    {"code": "EG", "name": "Egypt"},
    {"code": "NG", "name": "Nigeria"},
    {"code": "MX", "name": "Mexico"}
]

def load_data():
    if not os.path.exists(data_file):
        return {
            "blocked_countries": [], "blocked_asns": [], "settings": [], "last_update": "", "whitelist_ips": [], "blocked_ips": []}
    with open(data_file, 'r') as f:
        return json.load(f)

def save_data(data):
    with open(data_file, 'w') as f:
        json.dump(data, f, indent=4)

@app.template_filter('b64encode')
def b64encode_filter(s):
    return base64.b64encode(s.encode('utf-8')).decode('utf-8')

@app.route('/')
def index():
    data = load_data()
    return render_template('index.html', countries=data['blocked_countries'], asns=data['blocked_asns'], settings=data['settings'], countries_list=countries_list, whitelist_ips=data['whitelist_ips'], blocked_ips=data['blocked_ips'])
@app.route('/add_country', methods=['POST'])
def add_country():
    country_code = request.form['country_code']
    speed_limit = request.form.get('speed_limit')
    if country_code:
        data = load_data()
        if country_code.upper() not in data['blocked_countries']:
            data['blocked_countries'].append(country_code.upper())
            if speed_limit:
                data['settings'].append({"setting_name": f"speed_limit_{country_code.lower()}", "setting_value": speed_limit})
            save_data(data)
            subprocess.Popen(['python', 'update_mikrotik.py', '--force_update'])
    return redirect('/')

@app.route('/delete_country/<country_code>', methods=['POST'])
def delete_country(country_code):
    data = load_data()
    if country_code.upper() in data['blocked_countries']:
        data['blocked_countries'].remove(country_code.upper())
        data['settings'] = [setting for setting in data['settings'] if setting['setting_name'] != f"speed_limit_{country_code.lower()}"]
        save_data(data)
        subprocess.Popen(['python', 'update_mikrotik.py', '--remove_country', country_code])
    return redirect('/')

@app.route('/add_asn', methods=['POST'])
def add_asn():
    asn = request.form['asn']
    speed_limit = request.form.get('speed_limit')
    if asn:
        data = load_data()
        if asn.upper() not in data['blocked_asns']:
            data['blocked_asns'].append(asn.upper())
            if speed_limit:
                data['settings'].append({"setting_name": f"speed_limit_asn_{asn}", "setting_value": speed_limit})
            save_data(data)
            subprocess.Popen(['python', 'update_mikrotik.py', '--force_update'])
    return redirect('/')

@app.route('/delete_asn/<asn>', methods=['POST'])
def delete_asn(asn):
    data = load_data()
    if asn.upper() in data['blocked_asns']:
        data['blocked_asns'].remove(asn.upper())
        data['settings'] = [setting for setting in data['settings'] if setting['setting_name'] != f"speed_limit_asn_{asn}"]
        save_data(data)
        subprocess.Popen(['python', 'update_mikrotik.py', '--remove_asn', asn])
    return redirect('/')
@app.route('/add_ip', methods=['POST'])
def add_ip():
    ip = request.form['ip']
    list_type = request.form['list_type']
    if ip and list_type:
        data = load_data()
        if list_type == 'whitelist':
            if ip not in data['whitelist_ips']:
                data['whitelist_ips'].append(ip)
                save_data(data)
                subprocess.Popen(['python', 'update_mikrotik.py', '--add_whitelist', ip])
        elif list_type == 'blocklist':
            if ip not in data['blocked_ips']:
                data['blocked_ips'].append(ip)
                save_data(data)
                subprocess.Popen(['python', 'update_mikrotik.py', '--add_blocklist', ip])
    return redirect('/')

@app.route('/delete_ip/<list_type>/<ip>', methods=['POST'])
def delete_ip(list_type, ip):
    data = load_data()
    decoded_ip = base64.b64decode(ip).decode('utf-8')
    if list_type == 'whitelist' and decoded_ip in data['whitelist_ips']:
        data['whitelist_ips'].remove(decoded_ip)
        save_data(data)
        subprocess.Popen(['python', 'update_mikrotik.py', '--remove_whitelist', decoded_ip])
    elif list_type == 'blocklist' and decoded_ip in data['blocked_ips']:
        data['blocked_ips'].remove(decoded_ip)
        save_data(data)
        subprocess.Popen(['python', 'update_mikrotik.py', '--remove_blocklist', decoded_ip])
    return redirect('/')

@app.route('/add_setting', methods=['POST'])
def add_setting():
    setting_name = request.form['setting_name']
    setting_value = request.form['setting_value']
    if setting_name and setting_value:
        data = load_data()
        data['settings'].append({"setting_name": setting_name, "setting_value": setting_value})
        save_data(data)
    return redirect('/')

@app.route('/update_setting', methods=['POST'])
def update_setting():
    setting_name = request.form['setting_name']
    setting_value = request.form['setting_value']
    data = load_data()
    for setting in data['settings']:
        if setting['setting_name'] == setting_name:
            setting['setting_value'] = setting_value
            break
    save_data(data)
    return redirect('/')
@app.route('/delete_setting/<setting_name>', methods=['POST'])
def delete_setting(setting_name):
    data = load_data()
    data['settings'] = [setting for setting in data['settings'] if setting['setting_name'] != setting_name]
    save_data(data)
    return redirect('/')

if __name__ == '__main__':
    app.run(host='0.0.0.0')
