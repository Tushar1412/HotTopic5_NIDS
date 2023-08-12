from abc import abstractmethod
from scapy.all import *
from scapy.layers.inet import IP, TCP
from tcpFlags import of_string

class Option:
    def __init__(self, text):
        self.text = text

    def __repr__(self):
        return self.__class__.__name__ + ' ' + self.text

    @abstractmethod
    def match(self, packet):
        pass

class Tos(Option):
    def __init__(self, text):
        super().__init__(text)
        self.tos = int(text)

    def match(self, packet):
        return self.tos == packet[IP].tos

class Len(Option):
    def __init__(self, text):
        super().__init__(text)
        self.len = int(text)

    def match(self, packet):
        return self.len == packet[IP].ihl * 4

class Offset(Option):
    def __init__(self, text):
        super().__init__(text)
        self.offset = int(text)

    def match(self, packet):
        return self.offset == packet[IP].frag

class Seq(Option):
    def __init__(self, text):
        super().__init__(text)
        self.seq = int(text)

    def match(self, packet):
        return self.seq == packet[TCP].seq

class Ack(Option):
    def __init__(self, text):
        super().__init__(text)
        self.ack = int(text)

    def match(self, packet):
        return self.ack == packet[TCP].ack

class Flags(Option):
    def __init__(self, text):
        super().__init__(text)
        self.flags = of_string(text)

    def match(self, packet):
        return self.flags == (self.flags & packet[TCP].flags)

class HttpRequest(Option):
    def __init__(self, text):
        super().__init__(text)
        self.httpRequest = text

    def match(self, packet):
        payload = packet[IP].payload.payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', 'backslashreplace')
        return payload.startswith(self.httpRequest)

class Content(Option):
    def __init__(self, text):
        super().__init__(text)
        self.content = text

    def match(self, packet):
        payload = packet[IP].payload.payload
        if isinstance(payload, bytes):
            payload = payload.decode('utf-8', 'backslashreplace')
        return self.content in payload

def is_nmap_scan(packet):
    if packet.haslayer(TCP) and packet[TCP].flags in (2, 18):  # SYN or ACK flag
        return True
    return False

def main():
    if len(sys.argv) != 2:
        print("Usage: python run.py <rules_file>")
        return

    rules_file = sys.argv[1]
    rules = load_rules(rules_file)

    empty_rule = Rule('alert any any any -> any any (msg:"No rules matched";)', empty=True)

    sniff_packets(rules, empty_rule)

def load_rules(file_path):
    rm = RuleMaker(file_path)
    return rm.get_rules()

def is_matched(_packet, _rules):
    for rule in _rules:
        if rule.match(_packet):
            return rule.get_formatted(_packet)
    return empty_rule.get_formatted(_packet)

def sniff_packets(rules, empty_rule):
    sniff(filter="tcp", prn=lambda x: process_packet(x, rules, empty_rule))

def process_packet(packet, rules, empty_rule):
    if is_nmap_scan(packet):
        print(is_matched(packet, rules))

if __name__ == "__main__":
    main()
