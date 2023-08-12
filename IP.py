from netaddr import IPNetwork as IPN

class MyIPNetwork:
    def __init__(self, text):
        if text == "any":
            self.any = True
        else:
            self.any = False
            self.ipn = IPN(text)

    def __repr__(self):
        return "Any IP Address" if self.any else f"IP Range: {self.ipn}"

    def match(self, ip):
        return self.any or ip in self.ipn

# Example usage:
if __name__ == "__main__":
    input_text = input("Enter 'any' or an IP range: ")
    user_ip = input("Enter an IP address to check: ")

    ip_network = MyIPNetwork(input_text)
    is_match = ip_network.match(user_ip)

    print(f"The provided IP {user_ip} matches the criteria: {is_match}")
