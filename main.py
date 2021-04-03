#/usr/bin/python3

import dpkt
import socket
import urllib.request
import json
from colorama import Back, Fore
import optparse
import signal


p = optparse.OptionParser()
p.add_option('-p', dest='pcap', type='string',help='Pcap file for parsing')
(options, args) = p.parse_args()
pcap = options.pcap

def keyboardInterruptHandler(signal, frame):
    print("\nkilled.".format(signal))
    exit(0)

signal.signal(signal.SIGINT, keyboardInterruptHandler)



def geoloc(ip):
    try:
        url = "http://ip-api.com/json/"
        response = urllib.request.urlopen(url + ip)
        data = response.read()
        values = json.loads(data)
        country = values['country']
        city = values['city']
        if country != '':
            geoloc = city + '/' + country
        else:
            geoloc = country
        return geoloc
    except:
    
        print('\n'+Back.RED+"Not Found"+Back.RESET+'\n')
        
def parser(pcapfile):
    
    for (ts,buf) in pcapfile:
        try:

            eth = dpkt.ethernet.Ethernet(buf)            
            ip = eth.data
            tcp = ip.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
          
            
            if tcp.dport == 80 and len(tcp.data) > 0:
                
                http = dpkt.http.Request(tcp.data)
                print(Fore.GREEN+http.uri+Fore.RESET)
                print(Fore.GREEN+http.headers['user-agent']+Fore.RESET)
                print(Fore.CYAN+f"[+] Src: {src} --> Dst: {dst}"+Fore.RESET)
                print(Fore.YELLOW+"[+] Src: " + geoloc(src) + " --> Dst: " + geoloc(dst)+Fore.RESET+'\n')

            else:

                print(Fore.CYAN+f"[+] Src: {src} --> Dst: {dst}"+Fore.RESET)
                print(Fore.YELLOW+"[+] Src: " + geoloc(src) + " --> Dst: " + geoloc(dst)+Fore.RESET+'\n')
        except:
            pass

def main():
    if pcap == None:
        print('\nUsage: python3 program.py -p < PCAP FILE >\n')
    else:
        f = open(pcap, 'rb')
        pcapfile = dpkt.pcap.Reader(f)
        parser(pcapfile)

if __name__ == '__main__':

    main()

    

