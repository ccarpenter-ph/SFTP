import xml.etree.ElementTree as ET
import subprocess
from datetime import datetime
import argparse 
from pathlib import Path

# TODO: Wrap command into python script
# TODO: Add verbosity (create schema for storing host data, output more than hostname per compliant/noncompliant on -v)

# Vars
bad_hosts = [] # Hostname strings only
queried_hosts = [] # Hostname strings only
unresponsive_hosts = [] # Hostname strings only
noncompliant_hosts = [] # Host objects
compliant_hosts = [] # Host objects
current_datetime = datetime.now()
datetime_string = current_datetime.strftime("%Y%m%d-%H%M%S")

# Parse arguments
desc = "This script takes a list of hosts in a plaintext file format and - using a local installation of nmap - checks whether or not the algorithms they are using for SSH are FIPS compliant."

ap = argparse.ArgumentParser(description=desc)
ap.add_argument('host_list', type=str, help="Input file, a list of hosts in plaintext to test.")
ap.add_argument('-o', '--output', type=str, help="File name to export results to.")
ap.add_argument('-n', '--nmap', type=str, default="nmap/nmap.exe", help="Path to a local nmap installation. Defaults to ./nmap/nmap.exe.")
ap.add_argument('-v', '--verbose', action='store_true', help="Increase verbosity of output.")

args = ap.parse_args()
host_list_path = args.host_list
nmap_path = args.nmap
output_path = args.output
verbose = args.verbose # boolean

# Create output file if output_path is defined.
file_out = open(output_path, 'w') if output_path else None

# Ensure nmap output directory exists, or create it
ensure_nmap_out_dir = Path("nmap_out")
ensure_nmap_out_dir.mkdir(parents=True, exist_ok=True)

# Store list of hosts being queried from the input file, for cross-reference later. Also a good check to raise an error if the specified file doesn't exist
with open(host_list_path) as file:
    queried_hosts = [line.rstrip() for line in file]

# Run Nmap and parse output xml file
print("Running nmap...")
try:
    result = subprocess.run([nmap_path, '--script', 'ssh2-enum-algos', '-iL', host_list_path, '-oX', 'nmap_out/'+datetime_string+'.xml', '-p', '22'], capture_output=True, text=True, check=True)
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
    "aes192-gcm@openssh.com",
    "aes192-ctr",
    "aes192-cbc",
    "aes128-gcm@openssh.com",
    "aes128-ctr",
    "aes128-cbc"
    ]

# Evaluate nmap output and compliance of each host
unresponsive_hosts = queried_hosts.copy() # initialize unresponsive hosts to a copy of the queried hosts list; remove them as we go through the responsive hosts to return a list of the unresponsive ones
for host in hosts:
    host_data = {}
    hostname =""
    # Get hostname of the given host
    hostnames = host.findall('./hostnames/hostname')
    if hostnames:
        hostname = [hostname.get('name') for hostname in hostnames if hostname.get('type') == "user"][0]
    else: 
        # No hostnames, IP only
        hostname = [ip.get('addr') for ip in host.findall('./address') if ip.get('addrtype') == "ipv4"][0]

    host_data['hostname'] = hostname

    # Host was found, so remove it from our unresponsive host list
    unresponsive_hosts.pop(unresponsive_hosts.index(hostname))

    # Find listening SSH service on port 22
    ssh_port = [port for port in host.findall('./ports/port') if port.get('portid') == "22" and port.find('state').get('state') == "open" ]
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
output = ""

def verbose_host_output(host):
    global output

    output += "    Compliant Key Exchange Algorithms:\n"
    for algo in host['compliant_kex']:
        output += ("    - "+algo+"\n")
    
    output += "    Compliant Encryption Algorithms:\n"
    for algo in host['compliant_ciphers']:
        output += ("    - "+algo+"\n")

    output += "    Noncompliant Key Exchange Algorithms:\n"
    for algo in host['noncompliant_kex']:
        output += ("    - "+algo+"\n")
    
    output += "    Noncompliant Encryption Algorithms:\n"
    for algo in host['noncompliant_ciphers']:
        output += ("    - "+algo+"\n")

output += ("COMPLIANT HOSTS: ["+str(len(compliant_hosts))+"]\n")
if compliant_hosts:
    for host in compliant_hosts: 
        output += ("- "+host['hostname']+"\n") 
        if verbose: verbose_host_output(host)
else: output += "  [None]\n"

output += ("NONCOMPLIANT HOSTS: ["+str(len(noncompliant_hosts))+"]\n")
if noncompliant_hosts:
    for host in noncompliant_hosts: 
        output += ("- "+host['hostname']+"\n")
        if verbose: verbose_host_output(host)
else: output += "  [None]\n"

output += ("NON-SFTP HOSTS: ["+str(len(bad_hosts))+"]\n")
if bad_hosts:
    for host in bad_hosts:
        output += ("- "+host+"\n")
else: output += "  [None]\n"

output += ("UNRESPONSIVE HOSTS: ["+str(len(unresponsive_hosts))+"]\n")
if unresponsive_hosts:
    for host in unresponsive_hosts:
        output += ("- "+host+"\n")
else: output += "  [None]\n"

output += "\n\n===== SUMMARY =====\n"
output += ("COMPLIANT HOSTS: ["+str(len(compliant_hosts))+"]\n")
output += ("NONCOMPLIANT HOSTS: ["+str(len(noncompliant_hosts))+"]\n")
output += ("NON-SFTP HOSTS: ["+str(len(bad_hosts))+"]\n")
output += ("UNRESPONSIVE HOSTS: ["+str(len(unresponsive_hosts))+"]\n")
output += ("TOTAL: ["+str(len(queried_hosts))+"]\n")

print(output)
if file_out:
    file_out.write(output)
    file_out.close()




