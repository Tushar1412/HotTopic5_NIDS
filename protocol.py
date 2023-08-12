from scapy.all import *
from scapy.layers.inet import TCP, UDP

# List of HTTP methods to check for
HTTP_METHODS = [b'HTTP', b'GET', b'HEAD', b'POST', b'PUT', b'DELETE', b'CONNECT', b'OPTIONS', b'TRACE', b'PATCH']

class Protocol:
    def __init__(self, text):
        if text not in ['tcp', 'udp', 'http', 'any']:
            raise ValueError("Invalid protocol: " + text)
        
        self.any = False
        self.protocol = text
        
        if text == 'any':
            self.any = True

    def __repr__(self):
        if self.any:
            return "Any Protocol"
        return "Protocol: " + self.protocol.upper()

    def match(self, _packet):
        if self.any:
            return True
        
        if self.protocol == "udp":
            return UDP in _packet
        elif self.protocol == "tcp":
            return TCP in _packet
        elif self.protocol == "http" and TCP in _packet:
            return is_http(_packet)
        
        return False

def is_http(_packet):
    if TCP in _packet and _packet[TCP].payload:
        content = _packet[TCP].load
        if any(content.startswith(method) for method in HTTP_METHODS):
            return True
    return False
