from scapy.layers.inet import IP, TCP, UDP
from IP import IPNetwork
from scapy.all import *
from option import *
from port import Port
from protocol import Protocol, is_http

long_flags = dict(F='FIN', S='SYN', R='RST', P='PSH', A='ACK', U='URG', E='ECE', C='CWR')

def red(x):
    return '\033[91m' + x + '\033[0m'

def blue(x):
    return '\033[94m' + x + '\033[0m'

class Rule:
    def __init__(self, text, empty=False):
        self.text = text
        self.empty = empty
        words = text.split(' ', 7)
        options = words[-1].strip()[1:-1].split(';')
        self.protocol = Protocol(words[1])
        self.srcIP = IPNetwork(words[2])
        self.srcPort = Port(words[3])
        self.dstIP = IPNetwork(words[5])
        self.dstPort = Port(words[6])
        self.options = []
        
        # Initialize options based on their type
        for option in options:
            if option.strip() == '':
                break
            option_type, data = option.split(':', 1)
            if option_type == 'msg':
                self.message = data[1:-1]
            elif option_type == 'tos':
                self.options.append(Tos(data))
            elif option_type == 'len':
                self.options.append(Len(data))
            elif option_type == 'offset':
                self.options.append(Offset(data))
            elif option_type == 'seq':
                self.options.append(Seq(data))
            elif option_type == 'ack':
                self.options.append(Ack(data))
            elif option_type == 'flags':
                self.options.append(Flags(data))
            elif option_type == 'http_request':
                self.options.append(HttpRequest(data[1:-1]))
            elif option_type == 'content':
                self.options.append(Content(data[1:-1]))
                self.content = data[1:-1]
            else:
                raise KeyError("Unrecognized option type")

    def __repr__(self):
        repr_string = f"Protocol {self.protocol}\n"
        repr_string += f"Source {self.srcIP} {self.srcPort}\n"
        repr_string += f"Destination {self.dstIP} {self.dstPort}\n"
        repr_string += f"Message : {self.message}\n"
        repr_string += f"{len(self.options)} options --\n"
        for r in self.options:
            repr_string += r.__repr__() + '\n'
        return repr_string

    def __str__(self):
        return self.text

    def match(self, _packet):
        if IP not in _packet:
            return False
        if not self.protocol.match(_packet):
            return False
        if not self.srcIP.match(_packet[IP].src):
            return False
        if not self.srcPort.match(_packet[IP].payload.sport):
            return False
        if not self.dstIP.match(_packet[IP].dst):
            return False
        if not self.dstPort.match(_packet[IP].payload.dport):
            return False
        match_result = [f.match(_packet) for f in self.options]
        return all(match_result)

    def get_formatted(self, pkt):
        if IP not in pkt:
            return ''
        if not self.empty:
            val = f"Rule: {self.text}\n"
        else:
            val = "No rules matched!\n"
        val += "=====================\n"
        val += "[IP header]\n"
        
        # Include options with color highlights
        val += f"Version: {pkt[IP].version}\n"
        val += red(f"Header Length: {pkt[IP].ihl * 4} bytes\n") if check_option(self.options, pkt, Len) else f"Header Length: {pkt[IP].ihl * 4} bytes\n"
        val += red(f"ToS: {hex(pkt[IP].tos)}\n") if check_option(self.options, pkt, Tos) else f"ToS: {hex(pkt[IP].tos)}\n"
        val += red(f"Fragment Offset: {pkt[IP].frag}\n") if check_option(self.options, pkt, Offset) else f"Fragment Offset: {pkt[IP].frag}\n"
        val += red(f"Source: {pkt[IP].src}\n") if not self.srcIP.any and self.srcIP.match(pkt[IP].src) else f"Source: {pkt[IP].src}\n"
        val += red(f"Destination: {pkt[IP].dst}\n") if not self.dstIP.any and self.dstIP.match(pkt[IP].dst) else f"Destination: {pkt[IP].dst}\n"
        val += '\n'

        # Include options for TCP header
        if TCP in pkt:
            val += "[TCP header]\n"
            val += red(f"Source Port: {pkt[TCP].sport}\n") if not self.srcPort.any and self.srcPort.match(pkt[TCP].sport) else f"Source Port: {pkt[TCP].sport}\n"
            val += red(f"Destination Port: {pkt[TCP].d
