import re
import json

class LogParser:
    def __init__(self, pattern):
        self.pattern = pattern

    def parse_line(self, line):
        match = re.search(self.pattern, line)
        if match:
            return match.groupdict()
        return None

    def to_json(self, data):
        return json.dumps(data, indent=4, ensure_ascii=False)