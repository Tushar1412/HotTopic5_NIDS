#!/usr/bin/python3
import sys
from scapy.all import *
from rule import Rule
from RuleMaker import RuleMaker

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
    sniff(prn=lambda x: print(is_matched(x, rules)), filter="tcp or udp")

if __name__ == "__main__":
    main()
