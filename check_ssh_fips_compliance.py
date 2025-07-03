import xml.etree.ElementTree as ET
import subprocess
from datetime import datetime
import argparse 
import logging

# Vars
bad_hosts = []
noncompliant_hosts = []
compliant_hosts = []
current_datetime = datetime.now()
datetime_string = current_datetime.strftime("%Y%m%d-%H%M%S")

# Parse arguments
desc = "This script takes a list of hosts in a plaintext file format and - using a local installation of nmap - checks whether or not the algorithms they are using for SSH are FIPS compliant."

ap = argparse.ArgumentParser(description=desc)
ap.add_argument('host_list', type=str, help="Input file, a list of hosts in plaintext to test.")
ap.add_argument('-o', '--output', type=str, help="File name to export results to.")
ap.add_argument('-n', '--nmap', type=str, default="nmap/nmap.exe", help="Path to a local nmap installation. Defaults to ./nmap/nmap.exe.")
ap.add_argument('-v', '--verbose', action='store_true', help="Increase verbosity of output.")
ap.add_argument('-l', '--log', type=str, help="Path to store more verbose logging output from the script.")

args = ap.parse_args()
host_list_path = args.host_list
nmap_path = args.nmap
output_path = args.output
verbose = args.verbose # boolean
log_path = args.log

# Config logger based on arguments
log_config_args = {
    'level':logging.DEBUG,
    'format':'%(asctime)s %(name)-12s %(levelname)-8s %(message)s',
    'datefmt':'%m-%d %H:%M'
    }
if log_path: log_config_args.update({
    'filename':log_path,
    'filemode':'x'
})

logging.basicConfig(log_config_args)

console = logging.StreamHandler()
console.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)-12s: %(levelname)-8s %(messaage)s')
console.setFormatter(formatter)
logging.getLogger().addHandler(console)


# Create output file if args.output now, to catch errors early if it exists
if output_path: file_out = open(output_path, 'x')

# Run Nmap and parse output xml file
print("Running nmap...")
try:
    result = subprocess.run([nmap_path, '--script', 'ssh2-enum-algos', '-iL', host_list_path, '-oX', 'nmap_out/'+datetime_string+'.xml'], capture_output=True, text=True, check=True)
except subprocess.CalledProcessError as err:
    print("Something went wrong while running nmap. Printing stderr...")
    print(err.stderr)
    raise
 
if verbose: print(result.stdout)

tree = ET.parse('nmap_out/'+datetime_string+'.xml')
root = tree.getroot()

hosts = root.findall('host')

# Approved FIPS 140-2 algorithms. Only one must match to work
fips_kex_algos = [
    "ecdh-sha2-nistp256",
    "ecdh-sha2-nistp384",
    "ecdh-sha2-nistp521",
    "diffie-hellman-group-exchange-sha256",
    "diffie-hellman-group14-sha256",
    "diffie-hellman-group16-sha512",
    "diffie-hellman-group18-sha512"
    ]
fips_enc_algos = [
    "aes256-gcm@openssh.com",
    "aes256-ctr",
    "aes256-cbc",
    "aes128-gcm@openssh.com",
    "aes128-ctr",
    "aes128-cbc"
    ]

# Evaluate nmap output and compliance of each host
for host in hosts:
    host_data = {}

    # Get hostname of the given host
    hostname = host_data['hostname'] = [hostname.get('name') for hostname in host.findall('./hostnames/hostname') if hostname.get('type') == "user"][0] 

    # Find listening SSH service on port 22
    ssh_port = [port for port in host.findall('./ports/port') if port.get('portid') == "22" and port.find('service').get('name') == "ssh" ]
    # Report any hosts that are NOT hosting SSH on this port for re-check
    if not ssh_port:
        bad_hosts.append(hostname)
        continue
    else:
        # Select singleton item from list 
        ssh_port = ssh_port[0]

    table_script = [script for script in ssh_port.findall('script') if script.get('id') == "ssh2-enum-algos"][0]

    # Get list of key exchange algorithms
    kex_table = [table for table in table_script.findall('table') if table.get('key') == "kex_algorithms"][0]
    kex_algos = [algo.text for algo in kex_table.findall('elem')]

    # Get list of encryption algorithms
    enc_table = [table for table in table_script.findall('table') if table.get('key') == "encryption_algorithms"][0]
    enc_algos = [algo.text for algo in enc_table.findall('elem')]

    # Check FIPS compliant ciphers
    cipher_compliant = False
    compliant_enc_algos = host_data['compliant_ciphers'] = list(set(enc_algos).intersection(set(fips_enc_algos)))
    noncompliant_enc_algos = host_data['noncompliant_ciphers'] = list(set(enc_algos).difference(set(fips_enc_algos)))
    if compliant_enc_algos: cipher_compliant = True
        
    # Check FIPS compliant key exchange algorithms
    kex_compliant = False
    compliant_kex_algos = host_data['compliant_kex'] = list(set(kex_algos).intersection(set(fips_kex_algos)))
    noncompliant_kex_algos = host_data['noncompliant_kex'] = list(set(kex_algos).difference(set(fips_kex_algos)))
    if compliant_kex_algos: kex_compliant = True

    # Evaluate overall compliance and add to appropriate lists
    compliant = host_data['compliant'] = kex_compliant and cipher_compliant
    if compliant:
        compliant_hosts.append(host_data)
    else:
        noncompliant_hosts.append(host_data)

# Output results
print("COMPLIANT HOSTS:")
if file_out: file_out.write("COMPLIANT HOSTS:")
for host in compliant_hosts: 
    print("- "+host['hostname']) if not verbose else print("- "+str(host))
    if file_out:file_out.write("\n- "+host['hostname']) if not verbose else file_out.write("\n- "+str(host))
print("NONCOMPLIANT HOSTS:")
if file_out: file_out.write("\nNONCOMPLIANT HOSTS:")
for host in noncompliant_hosts: 
    print("- "+host['hostname']) if not verbose else print("- "+str(host))
    if file_out: file_out.write("\n- "+host['hostname']) if not verbose else file_out.write("\n- "+str(host))
print("UNRESPONSIVE HOSTS:")

file_out.close()




