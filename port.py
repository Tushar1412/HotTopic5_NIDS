class Port:
    def __init__(self, text):
        self.text = text
        self.any = False
        self.portList = set()

        if text == "any":
            self.any = True
        else:
            self.parse_ports(text)

    def __repr__(self):
        if self.any:
            return "Any Port"
        else:
            return "Port: " + self.text

    def parse_ports(self, text):
        """
        Parse the input text to create a list of port numbers or ranges.
        """
        if ':' in text:
            start, end = map(int, text.split(':'))
            self.portList.update(range(start, end + 1))
        elif ',' in text:
            self.portList.update(map(int, text.split(',')))
        else:
            self.portList.add(int(text))

    def match(self, port):
        """
        Check if the provided port matches the criteria set by the Port object.
        """
        return self.any or port in self.portList

    def is_nmap_port_scan(self, packet):
        """
        Check if the packet indicates an Nmap port scan.
        """
        return packet.haslayer(TCP) and (packet[TCP].flags == 2 or packet[TCP].flags == 18)
