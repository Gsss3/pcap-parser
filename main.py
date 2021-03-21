import dpkt
import socket
import urllib.request
import json
from colorama import Back, Fore
import optparse

p = optparse.OptionParser()
p.add_option('-p', dest='pcap', type='string',help='Pcap file for parsing')
(options, args) = p.parse_args()
pcap = options.pcap

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
        print(Fore.RED+"Not Found")
        print('\033[39m')
        
def parser(pcapfile):

    for (ts,buf) in pcapfile:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            
            print(Fore.CYAN+"[+] Src: {} --> Dst: {}".format(src,dst))
            print(Fore.YELLOW+"[+] Src: " + geoloc(src) + " --> Dst: " + geoloc(dst))
            print('\033[39m')

        except:
            pass

def main():
    if pcap == None:
        print('Usage: python3 program.py -p < PCAP FILE >')
    else:
        f = open(pcap, 'rb')
        pcapfile = dpkt.pcap.Reader(f)
        parser(pcapfile)

if __name__ == '__main__':
    main()

