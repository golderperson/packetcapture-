import scapy.all as scapy
from scapy.layers import http
import argparse
import httpcapture
import http2capture
import scan


def get_args():  # command option
    parser = argparse.ArgumentParser()
    parser.add_argument('-i', '--interface', dest='interface',
                        help='Interface Name for which packet is supposed to be captured.')
    parser.add_argument('-p', '--protocol', dest='protocol',
                        help='protocol Name for which packet is supposed to be captured.')
    parser.add_argument('-m', '--mode', dest='mode',
                        help='protocol Name for which packet is supposed to be captured.')
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Adresses')
    options = parser.parse_args()
    if options.mode == "scan":
        if not options.target:
        #Code to handle if interface is not specified
           parser.error("[-] Please specify an IP Address or Addresses, use --help for more info.")
        scanned_output = scan.scan(options.target)
        scan.display_result(scanned_output)
    elif not options.mode:
        if not options.interface or not options.protocol:
            parser.error(
                '[-] Please specify the name of the interface and protocol, use --help for more info.')
        interface = options.interface
        protocol = options.protocol
        if protocol == "http":  # http
            httpcapture.sniffer(interface)
        if protocol == "http2":  # http2
            http2capture.capture(interface)


get_args()
