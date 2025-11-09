# bRadar
![License](https://img.shields.io/badge/License-MIT-blue)
![Python](https://img.shields.io/badge/Python-3.11.9-brightgreen)

A real-time port scan activity detection tool.
```
   __   ___          __        
  / /  / _ \___ ____/ /__ _____
 / _ \/ , _/ _ `/ _  / _ `/ __/
/_.__/_/|_|\_,_/\_,_/\_,_/_/      
Port Scanning Detection Tool
@v1.00          by harshs0ni
```

## Installation :point_down:
```bash
git clone https://github.com/harshs0ni/bRadar.git
cd bRadar
pip install -r requirements.txt
```
## You Are Ready To Go :thumbsup:
Usage
```
Usage:
  Real time: sudo python3 bRadar.py -r -i <interface> -t <threshold>
  Read PCAP file: sudo python3 bRadar.py -f <path_to_pcap_file> -t <threshold>

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
```
## Example Command For Live Detection
```
 sudo python3 bRadar.py -r -i eth0 -t 1
```
## Example Command for Analyzing an Existing PCAP File
```
 sudo python3 bRadar.py -f saved_pcap_file_name.pcap -t 1
```
## Output Example 👇
```
-------------- [*] Realtime Detection has been started! --------------
----------------------------------------------------------------------
[info] Threshold: 80
[info] Interface: eth0

[+] [ 2025-11-09 05:42:38 ]  Potential port scanning activity detected from *.*.*.*, scan reached 80 ports.
^C
----------------------------------------------------------------------
```
## Features
```
- Real-time port scan detection
- Alerts suspicious IPs
- Save packets to PCAP (-p)
- Save alerts to text file (-s)
- Adjustable detection sensitivity (-t)
```

## Contributing
Contributions are welcome! However, please **contact me privately first** before opening issues or submitting pull requests.  
This helps ensure security and proper coordination.  

Once approved, you can help by:
- Reporting bugs or issues
- Suggesting improvements
- Submitting pull requests for new features or fixes


## Contacts :point_down:

[Instagram](https://instagram.com/harshs0ni__) [Twitter](https://twitter.com/harshs0ni__) [Github](https://github.com/harshs0ni) [Medium](https://harshs0n1.medium.com)
