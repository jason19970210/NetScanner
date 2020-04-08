import nmap
import nmap3
import sys, json, os
import socket
import netifaces as ni
import prettytable as pt
import inquirer
                                                                          
nmap3 = nmap3.Nmap()
nmap = nmap.PortScanner()

## Command Line Colors
Red = '\33[31m'
N = '\33[0m'

# https://www.cnblogs.com/hester/p/7552401.html

netifaces_doc = 'For More Information please check: https://pypi.org/project/netifaces/'
def getInterfaces():
    interfaces = ni.interfaces() #get interfaces list 
    inquirer_choice = [] #create an empty list to store interface & ip
    for interface in interfaces:
        if 'AF_INET' in dir(ni):
            try:
                #print(interface + ' : ', ni.ifaddresses(interface)[ni.AF_INET])
                info = ni.ifaddresses(interface)[ni.AF_INET][0]
                ip = info['addr']
                netmask = info['netmask']
                item = '{:<4} {:<15} {:<15}'.format(interface, ip, netmask)
                inquirer_choice.append(item)
            except:
                continue
        elif 'AF_PACKET' in dir(ni):
            try:
                #print(interface + ' : ', ni.ifaddresses(interface)[ni.AF_PACKET])
                info = ni.ifaddresses(interface)[ni.AF_PACKET][0]
                ip = info['addr']
                netmask = info['netmask']
                item = '{:<4} {:<15} {:<15}'.format(interface, ip, netmask)
                inquirer_choice.append(item)
            except:
                continue
        elif 'AF_LINK' in dir(ni):
            try:    
                #print(interface + ' : ', ni.ifaddresses(interface)[ni.AF_LINK])
                info = ni.ifaddresses(interface)[ni.AF_LINK][0]
                ip = info['addr']
                netmask = info['netmask']
                item = '{:<4} {:<15} {:<15}'.format(interface, ip, netmask)
                inquirer_choice.append(item)
            except:
                continue
        else:
            print("None of above")
            sys.exit()

    questions = [
        inquirer.List('Interface',
                       message = "Select The Interface: ",
                       choices = inquirer_choice
                    ),
    ]
    answers = inquirer.prompt(questions)
    select = answers['Interface'].split()
    #print(select[1])
    return select[1]


def getSubnet(ip_addr):
    #print(ip_addr)
    ip_addr = '.'.join(ip.split('.')[:-1]) + '.*'
    return ip_addr

#### Main
#Get ip
ip =  getInterfaces()
print('Scanning', getSubnet(ip), '...')
print('It will take some time to scan, please wait !')
scan_result = nmap.scan(getSubnet(ip))
hostlist = sorted(nmap.all_hosts(), key = socket.inet_aton) # sort the ip address


tb_host = pt.PrettyTable()
tb_top_ports = pt.PrettyTable()

tb_host.field_names = ['IP', 'MAC Address', 'OS Name', 'OS Accuracy', 'OS Family', 'Reason']
tb_top_ports.field_names = ['Port', 'Service', 'Protocol', 'State', 'Reason', 'Reason TTL']


for host in hostlist:
    inquirer_choice = []
    try:
        os_detection = nmap3.nmap_os_detection(host)[0]
        os_name = os_detection['name']
        os_accu = os_detection['accuracy']
        os_family = os_detection['osclass']['osfamily']
        #os_gen = os_detection['osclass']['osgen']
    except IndexError:
        os_name = os_accu = os_family = 'Null' #os_gen =

    ind_result = scan_result['scan'][host]
    ipv4 = ind_result['addresses']['ipv4']
    try:
        mac = ind_result['addresses']['mac']
    except KeyError:
        #print('No MAC Address')
        mac = 'null'
    hostname = ind_result['hostnames'][0]['name']
    #vendor = ind_result['vendor']
    #state = ind_result['status']['state']
    reason = ind_result['status']['reason']
    
    tb_host.add_row([ipv4, mac, os_name, os_accu, os_family, reason])

print(tb_host)

def select_target(ip_list):
    questions = [
        inquirer.List('ip_target',
                      message = 'Select Target: ',
                      choices = ip_list),#inquirer_choice

    ]
    answers = inquirer.prompt(questions)
    target = answers['ip_target']
    return target

ip_target = select_target(hostlist)

print('\n---------------OS Ports--------------\n')
for item in nmap3.scan_top_ports(ip_target):
    if item['state'] == 'open':
        tb_top_ports.add_row([Red+item['port']+N, Red+item['service']['name']+N, Red+item['protocol']+N, Red+item['state']+N, Red+item['reason']+N, Red+item['reason_ttl']+N])
    else:
        tb_top_ports.add_row([item['port'], item['service']['name'], item['protocol'], item['state'], item['reason'], item['reason_ttl']])
print(tb_top_ports)


print('\n---------------Service Version--------------\n')
tb_service_version = pt.PrettyTable()
tb_service_version.field_names = ['Protocol', 'Port', 'Service Name', 'Product', 'Version', 'ExtraInfo', 'OS Type', 'CPE'] #'Method', 'Conf',

for item in nmap3.nmap_version_detection(ip_target):
    # item = {'protocol': 'tcp', 'port': '135', 'service': {'name': 'msrpc', 'product': 'Microsoft Windows RPC', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
    if 'service' in item: # Linux & Windows cases
        protocol = item['protocol']
        port = item['port']
        name = item['service']['name']
        product = item['service']['product']
        os_type = item['service']['ostype'] if 'ostype' in item['service'] else 'Null'
        #method = item['service']['method']
        #conf = item['service']['conf']
        cpe = item['cpe'][0]['cpe']
        version = item['service']['version'] if 'version' in item['service'] else 'Null'
        extrainfo = item['service']['extrainfo'] if 'extrainfo' in item['service'] else "Null"
        #if 'version' in item['service']:
        #    version = item['service']['version']
    else: #iPhone case
        protocol = item['protocol']
        port = item['port']
        name = product = os_type = method = conf = cpe = version = extrainfo = "Null"
    tb_service_version.add_row([protocol, port, name, product, version, extrainfo, os_type, cpe]) #method, conf,
print(tb_service_version)

        
## Windows XP return >> ['protocol'], ['port'], ['service']['name'], ['service']['product'], ['service']['ostype'], ['service']['method'], ['service']['conf'], ['cpe'][0]['cpe'] >> 8
#    {'protocol': 'tcp', 'port': '135', 'service': {'name': 'msrpc', 'product': 'Microsoft Windows RPC', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#    {'protocol': 'tcp', 'port': '139', 'service': {'name': 'netbios-ssn', 'product': 'Microsoft Windows netbios-ssn', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#    {'protocol': 'tcp', 'port': '445', 'service': {'name': 'microsoft-ds', 'product': 'Microsoft Windows XP microsoft-ds', 'ostype': 'Windows XP', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows_xp'}]}
#    {'protocol': 'tcp', 'port': '3389', 'service': {'name': 'ms-wbt-server', 'product': 'Microsoft Terminal Services', 'ostype': 'Windows XP', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows_xp'}]}

## Windows 10 return >> ['protocol'], ['port'], ['service']['name'], ['service']['product'], ['service']['ostype'], ['service']['method'], ['service']['conf'], ['cpe'][0]['cpe'] >> 8
#   {'protocol': 'tcp', 'port': '135', 'service': {'name': 'msrpc', 'product': 'Microsoft Windows RPC', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#   {'protocol': 'tcp', 'port': '139', 'service': {'name': 'netbios-ssn', 'product': 'Microsoft Windows netbios-ssn', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#   {'protocol': 'tcp', 'port': '445', 'service': {'name': 'microsoft-ds', 'product': 'Microsoft Windows 7 - 10 microsoft-ds', 'extrainfo': 'workgroup: WORKGROUP', 'hostname': 'DESKTOP-6C0L7JQ', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#   {'protocol': 'tcp', 'port': '1947', 'service': {'name': 'http', 'product': 'Aladdin/SafeNet HASP license manager', 'version': '18.00', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}
#   {'protocol': 'tcp', 'port': '5357', 'service': {'name': 'http', 'product': 'Microsoft HTTPAPI httpd', 'version': '2.0', 'extrainfo': 'SSDP/UPnP', 'ostype': 'Windows', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:microsoft:windows'}]}

## Mac return

## iPhone return >> ['protocol'], ['port'] >> 2
#   {'protocol': 'tcp', 'port': '21'}
#   {'protocol': 'tcp', 'port': '53'}
#   {'protocol': 'tcp', 'port': '62078'}

## Linux return >> ['protocol'], ['port'], ['service']['name'], ['service']['product'], ['service']['version'], ['service']['extrainfo'], ['service']['ostype'], ['service']['method'], ['service']['conf'], ['cpe'][0]['cpe'] >> 10
#    {'protocol': 'tcp', 'port': '22', 'service': {'name': 'ssh', 'product': 'OpenSSH', 'version': '7.6p1 Ubuntu 4ubuntu0.3', 'extrainfo': 'Ubuntu Linux; protocol 2.0', 'ostype': 'Linux', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/o:linux:linux_kernel'}]}
#    {'protocol': 'tcp', 'port': '80', 'service': {'name': 'http', 'product': 'Apache httpd', 'version': '2.4.29', 'extrainfo': '(Ubuntu)', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/a:apache:http_server:2.4.29'}]}
#    {'protocol': 'tcp', 'port': '139', 'service': {'name': 'netbios-ssn', 'product': 'Samba smbd', 'version': '3.X - 4.X', 'extrainfo': 'workgroup: SANS', 'hostname': 'SIFTWORKSTATION', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/a:samba:samba'}]}
#    {'protocol': 'tcp', 'port': '445', 'service': {'name': 'netbios-ssn', 'product': 'Samba smbd', 'version': '3.X - 4.X', 'extrainfo': 'workgroup: SANS', 'hostname': 'SIFTWORKSTATION', 'method': 'probed', 'conf': '10'}, 'cpe': [{'cpe': 'cpe:/a:samba:samba'}]}


return_back_list = ['Re-scan Hosts', 'Re-select Host', 'Re-scan Ports', 'Re-scan Services Version', 'Exit']
questions = [
    inquirer.List('return_back',
                  message = 'Select Target: ',
                  choices = return_back_list),#inquirer_choice

]

answers = inquirer.prompt(questions)
print(answers)
