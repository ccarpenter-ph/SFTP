# How to use
You can get a list of optional arguments for this script using the -h flag.
It expects an input file of hosts as an argument, and by default will simply show compliant, noncompliant, non-sftp, and unresponsive hosts from a scan of that list.
It also expects a local installation of nmap; I recommend using a portable version in the same directory as the script, placed under a folder called nmap. By default, the script will look for nmap/nmap.exe to exist. If you wish to override this path, use the -n or --nmap flag and specify a new path to your nmap executable.