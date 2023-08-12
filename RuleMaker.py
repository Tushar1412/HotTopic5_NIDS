from rule import Rule

class RuleMaker:
    def __init__(self, file_path):
        self.rules = []

        with open(file_path, 'r') as f:
            for line in f:
                stripped_line = line.strip()
                if stripped_line:
                    self.rules.append(Rule(stripped_line))

    def get_rules(self):
        return self.rules

# Example usage:
if __name__ == "__main__":
    file_path = "rules.txt"  # Provide the path to your rules file
    rule_maker = RuleMaker(file_path)
    rules = rule_maker.get_rules()

    print("List of Rules:")
    for idx, rule in enumerate(rules, start=1):
        print(f"Rule {idx}: {rule}")
