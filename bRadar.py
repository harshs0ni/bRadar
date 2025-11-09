import sys,os
try:
    from scapy.all import rdpcap
    from scapy.all import sniff
    from scapy.utils import PcapWriter
    import scapy.all as scapy
except ModuleNotFoundError:
    print("[-] Error: Unable to Read Scapy. Either it is not installed or not installed properly")
    sys.exit(1)
try:
    import getopt, time, threading, signal, psutil,traceback
    from colorama import Fore, Style
except ModuleNotFoundError:
    print("[-] Error: Unable to import Modules")
    sys.exit(1)


print(Style.DIM + Fore.GREEN +r'''   __   ___          __        
  / /  / _ \___ ____/ /__ _____
 / _ \/ , _/ _ `/ _  / _ `/ __/
/_.__/_/|_|\_,_/\_,_/\_,_/_/      
Port Scanning Detection Tool
@v1.00          by harshs0ni

'''+ Style.RESET_ALL)

def usage():
    print('''Usage:\n  Real time: sudo python3 bRadar.py -r -i <interface> -t <threshold>\n  Read PCAP file: sudo python3 bRadar.py -f <path_to_pcap_file> -t <threshold>\n
Options:
  -r, --realtime                     Start live packet scanning immediately
  -f, --file <path_to_pcap_file>     Analyze packets from an existing PCAP file
  -i, --interface <interface>        Network interface to capture packets from
  -t, --threshold <level 1-3>        Port scan detection sensitivity level:
                                            1 = 20 ports
                                            2 = 80 ports
                                            3 = 150 ports
  -p, --pcap <desired_filename.pcap>       Save live captured packets into a PCAP file (only works during live detection)
  -s, --save <desired_filename>      Save detection alerts to a text file (Appends)
  -h, --help                         Show this help message and exit 
''')

threshold = 80
max_port_time = 300
ip_hashmap = {}
interface = None
realtime_state = False
readfile_state = False
filepath = None
save_output_path = None
blacklisted_ips = []
realtime_save_data =[]
pcapfilename_path = None
argumentList = sys.argv[1:]
short_arg = "rf:t:i:s:p:h"
long_arg = ["realtime", "file=","threshold=","interface=","save=","pcap=","help"]

try:
    arguments, values = getopt.getopt(argumentList, short_arg, long_arg)
    if not arguments:
        usage()
        sys.exit(1)
    for currentArgument, currentValue in arguments:
            
        if currentArgument in ("-r", "--realtime"):
            realtime_state = True
        elif currentArgument in ("-f", "--file"):
            readfile_state = True   
            filepath = currentValue
        elif currentArgument in ("-t", "--threshold"):
            currentValue = int(currentValue)
            if currentValue == 1:
                threshold = 20
            elif currentValue == 2:
                threshold = 80
            elif currentValue == 3:
                threshold = 150
            else:
                print("[-] Warning: Invalid level! Choose 1, 2, or 3.")
                sys.exit(1)
        elif currentArgument in ("-i", "--interface"):
            interface = currentValue
        elif currentArgument in ("-s", "--save"):
            save_output_path = currentValue
        elif currentArgument in ("-p", "--pcap"):
            pcapfilename_path = currentValue
        elif currentArgument in ("-h", "--help"):
            usage()
            sys.exit(0)


except getopt.error as err:
        if not readfile_state and not realtime_state:
            print("[-] Warning: Please mention the mode of detection")
        usage()
        sys.exit(0)


if readfile_state and realtime_state:
    print("[-] Warning: Please mention Single mode of detection")
    usage()
    sys.exit(0)

if readfile_state and not os.access(filepath, os.R_OK):
    print(f"[-] Error: File exists but is not readable (permission denied): {filepath}")
    sys.exit(1)

if pcapfilename_path and realtime_state:
    try:
        pcap_writer = PcapWriter(pcapfilename_path, append=True, sync=True)
    except Exception:
        print("[-] Error: Unable to create PCAP file")

if pcapfilename_path and readfile_state:
    print("[-] Warning: PCAP save option only works in realtime scanning mode")

def signal_handler(sig, frame):
    print("\n----------------------------------------------------------------------")
    if pcapfilename_path and realtime_state:
        pcap_writer.close()
        print("\n[+] PCAP file saved: ", pcapfilename_path)
    if save_output_path and realtime_state:
        updated = iter(blacklisted_ips)
        for ip, time in zip(updated, updated):
            save_file(f"[+] [ {time} ]  Potential port scanning activity detected from {ip}, Scanned a total of {len(ip_hashmap[ip])} ports.")
        print("\n[+] output file is saved: ", save_output_path)
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

def validate_interface(interface):
    if not interface:
        print("[-] Warning: Please specify a network interface")
        usage()
        sys.exit(1)
    interfaces = psutil.net_if_addrs().keys()
    if interface not in interfaces:
        print(f"[-] Error: '{interface}' is not a valid network interface.")
        print(f"[+] Available interfaces: {', '.join(interfaces)}")
        sys.exit(1)

def remove_old_entries():
    while True:
        time.sleep(10)
        for i in list(ip_hashmap.keys()):
            for j in list(ip_hashmap[i].keys()):
                diff = time.time() - ip_hashmap[i][j]
                if diff >= max_port_time:
                    ip_hashmap[i].pop(j, None)
            if not ip_hashmap[i]:
                ip_hashmap.pop(i)
            

def get_curr_time():
    curr_time_formatted = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    return curr_time_formatted

def save_file(output):
    if readfile_state:
        print(Style.BRIGHT + Fore.RED+output+Style.RESET_ALL)
    if save_output_path:
        try:
            with open(save_output_path, "a") as output_file:
                output_file.write(output+"\n")
        except Exception:
            print("[-] Error: Unable to save output in file")

def realtime_detection(interface,threshold):
    validate_interface(interface)
    print(f'''-------------- [*] Realtime Detection has been started! --------------
----------------------------------------------------------------------\n[info] Threshold: {threshold}\n[info] Interface: {interface}\n''')
    def process_sniffed_packet(packet):
        if pcapfilename_path:
            pcap_writer.write(packet)
        if packet.haslayer("IP") and packet.haslayer("TCP"):
            src_ip = str(packet['IP'].src)
            dst_port = str(packet['TCP'].dport)
            ip_hashmap.setdefault(src_ip, {})[dst_port] = time.time()
            if len(ip_hashmap[src_ip]) >= threshold and src_ip not in blacklisted_ips:
                ip_flagged_time = get_curr_time()
                blacklisted_ips.append(src_ip)
                blacklisted_ips.append(ip_flagged_time)
                print(Style.BRIGHT + Fore.RED+f"[+] [ {ip_flagged_time} ]  Potential port scanning activity detected from {src_ip}, scan reached {len(ip_hashmap[src_ip])} ports."+Style.RESET_ALL)
    try:
        sniff(iface=interface, store=False, prn=process_sniffed_packet)
    except Exception:
        print("[-] Error: There is some issues while reading packets.")
        return


def detection_through_pcapfile(filepath,threshold):
    print(f'''----------------- [*] File Analysis has been started! -----------------
-----------------------------------------------------------------------\n[info] Threshold: {threshold}\n''')
    def analyze_hashmap(hashmap):
        for i in hashmap:
            if len(hashmap[i]) >= threshold:
                save_file(f"[+] Potential port scanning activity detected from {i}, Scanned a total of {len(hashmap[i])} ports.")
                
    try:
        packets = rdpcap(filepath)
    except Exception:
        print("[-] Error: Unable to read file: ", filepath)
        sys.exit(1)
    for i in range(len(packets)):
        if packets[i].haslayer("IP") and packets[i].haslayer("TCP"):
            src_ip = str(packets[i]['IP'].src)
            dst_port = str(packets[i]['TCP'].dport)
            ip_hashmap.setdefault(src_ip, set()).add(dst_port)
    analyze_hashmap(ip_hashmap)
    print("\n-----------------------------------------------------------------------")
    if save_output_path and os.path.isfile(save_output_path):
        print("\n[+] output file is saved: ", save_output_path)

try:
    
    if realtime_state == True:
        cleanup_thread = threading.Thread(target=remove_old_entries, daemon=True)
        cleanup_thread.start()
        realtime_detection(interface,threshold)
    else:
        if readfile_state == True and filepath:
            detection_through_pcapfile(filepath,threshold)
except Exception as e:
    print(e,"\n----------------------Unexpected Error Occured!----------------------\n-----------------------------------------------------------------------")
    traceback.print_exc()
    sys.exit(0)