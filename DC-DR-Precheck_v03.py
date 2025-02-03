import requests
import getpass
import warnings
from urllib3.exceptions import InsecureRequestWarning
from tabulate import tabulate
from datetime import datetime

# Suppress only the single InsecureRequestWarning from urllib3 needed
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Function to obtain authentication token
class Authentication:

    @staticmethod
    def get_jsessionid(vmanage_host, vmanage_port, username, password):
        api = "/j_security_check"
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        url = base_url + api
        payload = {'j_username': username, 'j_password': password}

        response = requests.post(url=url, data=payload, verify=False)
        try:
            cookies = response.headers["Set-Cookie"]
            jsessionid = cookies.split(";")[0]
            if "JSESSIONID" in jsessionid:
                return jsessionid
            else:
                print("Login Failure: Check username/password.")
                exit()
        except KeyError:
            print("Login Failed: Unable to obtain JSESSIONID")
            exit()

    @staticmethod
    def get_token(vmanage_host, vmanage_port, jsessionid):
        headers = {'Cookie': jsessionid}
        base_url = f"https://{vmanage_host}:{vmanage_port}"
        api = "/dataservice/client/token"
        url = base_url + api
        response = requests.get(url=url, headers=headers, verify=False)
        if response.status_code == 200:
            return response.text
        else:
            print("Failed to obtain the XSRF token")
            return None

# Function to get DR data and print it
def get_device_list(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/disasterrecovery/localdc"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json()
        if isinstance(json_data, list):
            formatted_data = format_device_list(json_data)
            print_table(formatted_data, ["Data Center Name", "Host Name", "Device IP", "State"])
            return formatted_data
        else:
            print("Unexpected response format")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to get device list: {e}")
        exit()

def get_replication_details(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/disasterrecovery/details"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json()
        if "replicationDetails" in json_data:
            formatted_data = format_replication_details(json_data["replicationDetails"])
            print_table(formatted_data, ["Last Replicated", "Export Duration", "Export Size", "Replication Status"])
            return formatted_data
        else:
            print("Unexpected response format")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to get replication details: {e}")
        exit()

def get_dr_status(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/disasterrecovery/drstatus"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json()
        if isinstance(json_data, list):
            formatted_data = format_dr_status(json_data)
            print_table(formatted_data, ["Management IP", "Data Center Personality"])
            return formatted_data
        else:
            print("Unexpected response format")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to get disaster recovery status: {e}")
        exit()

def get_cluster_management_list(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/clusterManagement/list"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json().get("data", [])
        if isinstance(json_data, list):
            formatted_data = format_cluster_management_list(json_data)
            print_table(formatted_data, ["vManage ID", "UUID", "Host Name", "Device IP", "State", "Container Manager", "Persona"])
            return formatted_data
        else:
            print("Unexpected response format")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to get cluster management list: {e}")
        exit()

def get_reachability_list(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/clusterManagement/health/status"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json().get("data", [])
        if isinstance(json_data, list):
            formatted_data = format_reachability_list(json_data)
            print_table(formatted_data, ["Device IP", "Statistics DB", "Application Server", "Messaging Server", "Configuration DB"])
            return formatted_data
        else:
            print("Unexpected response format")
            return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to get reachability list: {e}")
        exit()

def get_vBond_list(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/device/monitor"
    try:
        response = requests.get(url, headers=headers, verify=False)
        response.raise_for_status()

        json_data = response.json().get("data", [])
        vbond_list = []
        i=0
        while i < len(json_data) :
            if(json_data[i]['device-type'] == 'vbond'): vbond_list.append(json_data[i]['system-ip'])
            i=i+1
        return vbond_list


    except requests.exceptions.RequestException as e:
        print(f"Failed to get reachability list: {e}")
        exit()

def get_serial_list(vmanage_host, vmanage_port, headers):
    vbond_list = get_vBond_list(vmanage_host, vmanage_port, headers)
    i=0
    temp_dict={}
    while i < len(vbond_list):
        url = f"https://{vmanage_host}:{vmanage_port}/dataservice/device/orchestrator/validvsmarts?deviceId="
        url = url+vbond_list[i]
        try:
            response = requests.get(url, headers=headers, verify=False)
            response.raise_for_status()

            json_data = response.json().get("data", [])
            if isinstance(json_data, list):
                formatted_data = format_serial_list(json_data)
                j=0
                temp_list =[]
                while j < len(formatted_data) : 
                    temp_list.append(formatted_data[j][2])
                    j=j+1
                temp_list.sort() 
                temp_dict[vbond_list[i]]=temp_list
                #print(formatted_data)
                print_table(formatted_data, ["vdevice-dataKey", "vdevice-name", "serial-number", "vdevice-host-name"])
            else:
                print("Unexpected response format")
                

        except requests.exceptions.RequestException as e:
            print(f"Failed to get reachability list: {e}")
            exit()

        i=i+1
    compare_vdevice_name(temp_dict,vbond_list)
    return None


def compare_vdevice_name(vDevice_dict,vbond_list):
    i=0
    while i < len(vbond_list) : 
        if vDevice_dict[vbond_list[0]] == vDevice_dict[vbond_list[i]] : print('vBond Check ' + str(i) + ' Passed')
        else : print('vBond Check ' + str(i) + ' Failed')
        i=i+1
    return None

def format_device_list(raw_data):
    formatted_data = []
    for item in raw_data:
        if 'dcName' in item and 'nodes' in item:
            nodes = [{'hostName': node['hostName'],
                      'deviceIP': node['deviceIP'],
                      'state': node['state']} for node in item['nodes']]
            formatted_data.append({
                'dcName': item['dcName'],
                'nodes': nodes
            })
    return formatted_data

def format_replication_details(raw_data):
    formatted_data = []
    for item in raw_data:
        last_replicated = datetime.fromtimestamp(item['lastReplicated'] / 1000).strftime('%Y-%m-%d %H:%M:%S')
        formatted_data.append([
            last_replicated,
            item['exportDuration'],
            item['exportSize'],
            item['replicationStatus']
        ])
    return formatted_data

def format_dr_status(raw_data):
    formatted_data = []
    for item in raw_data:
        formatted_data.append([
            item['mgmtIPAddress'],
            item['dcPersonality']
        ])
    return formatted_data

def format_cluster_management_list(raw_data):
    formatted_data = []
    for item in raw_data:
        if 'isIPConfigured' in item and item['isIPConfigured']:
            for data in item.get('data', []):
                config = data.get('configJson', {})
                formatted_data.append([
                    data.get('vmanageID', ''),
                    config.get('uuid', ''),
                    config.get('host-name', ''),
                    config.get('deviceIP', ''),
                    config.get('state', ''),
                    config.get('container-manager', ''),
                    config.get('persona', '')
                ])
    return formatted_data

def format_reachability_list(raw_data):
    formatted_data = []
    for item in raw_data:
        formatted_data.append([
            item.get('deviceIP', ''),
            item.get('statistics-db', False),
            item.get('application-server', False),
            item.get('messaging-server', False),
            item.get('configuration-db', False)
        ])
    return formatted_data

def format_serial_list(raw_data):
    formatted_data = []
    for item in raw_data:
        last_updated = datetime.fromtimestamp(item.get('lastupdated', 0) / 1000).strftime('%Y-%m-%d %H:%M:%S')
        formatted_data.append([
            item.get('vdevice-dataKey', ''),
            item.get('vdevice-name', ''),
            item.get('serial-number', ''),
            last_updated,
            item.get('vdevice-host-name', '')
        ])
    return formatted_data



def print_table(data, headers):
    table = []
    if headers[0] == "Data Center Name":  # Device list formatting
        for entry in data:
            dc_name = entry['dcName']
            for node in entry['nodes']:
                table.append([dc_name, node['hostName'], node['deviceIP'], node['state']])
    else:  # Other data formatting
        table.extend(data)

    print(tabulate(table, headers, tablefmt="grid"))

def sendtocontroller(vmanage_host, vmanage_port, headers):
    url = f"https://{vmanage_host}:{vmanage_port}/dataservice/certificate/vedge/list?action=push)"
    payload = {}
    try:
        response = requests.request("POST", url, headers=headers, data=payload, verify=False)
        json_data = response.json()
        print('Task Successful')
        print(json_data)
        return None

    except requests.exceptions.RequestException as e:
        print(f"Failed to push device list: {e}")
        exit()

def main(vmanage_host, vmanage_port, username, password):
    jsessionid = Authentication.get_jsessionid(vmanage_host, vmanage_port, username, password)
    token = Authentication.get_token(vmanage_host, vmanage_port, jsessionid)
    headers = {'Cookie': jsessionid, 'X-XSRF-TOKEN': token} if token else {'Cookie': jsessionid}

    dr_jsessionid = Authentication.get_jsessionid(dr_vmanage_host, vmanage_port, username, password)
    dr_token = Authentication.get_token(dr_vmanage_host, vmanage_port, dr_jsessionid)
    dr_headers = {'Cookie': dr_jsessionid, 'X-XSRF-TOKEN': dr_token} if dr_token else {'Cookie': dr_jsessionid}

    # Get and print device list
    print("\nDevice List:")
    get_device_list(vmanage_host, vmanage_port, headers)

    # Get and print replication details
    print("\nReplication Details:")
    get_replication_details(vmanage_host, vmanage_port, headers)

    # Get and print disaster recovery status
    print("\nDisaster Recovery Status:")
    get_dr_status(vmanage_host, vmanage_port, headers)

    # Get and print cluster_management_list status
    print("\nDisaster Recovery Status:")
    get_cluster_management_list(vmanage_host, vmanage_port, headers)


    # Get and print dr_cluster_management_list status
    print("\nDisaster Recovery Status:")
    get_cluster_management_list(dr_vmanage_host, vmanage_port, dr_headers)

    # Get and print cluster_reachability_list status
    print("\nDisaster Recovery Status:")
    get_reachability_list(vmanage_host, vmanage_port, headers)

    # Get and print dr_cluster_reachability_list status
    print("\nDisaster Recovery Status:")
    get_reachability_list(dr_vmanage_host, vmanage_port, dr_headers)
    
    # Get and print serial_list status
    print("\nDisaster Recovery Status:")
    get_serial_list(vmanage_host, vmanage_port, headers)
    
    # Post - Send to Controller
    print("\nSend to Controller :")
    sendtocontroller(vmanage_host, vmanage_port, headers)

if __name__ == '__main__':
    vmanage_host = input("vManage Host (e.g., '10.65.104.116'): ")
    vmanage_port = input("vManage Port (e.g., '8443'): ")
    username = input("Username: ")
    password = getpass.getpass("Password: ")
    dr_vmanage_host = input("dr_vManage Host (e.g., '10.65.104.116'): ")

    main(vmanage_host, vmanage_port, username, password)