from src.parser import LogParser

SSH_PATTERN = r"(?P<date>\w+\s+\d+\s+[\d:]+)\s+(?P<host>\S+)\s+(?P<service>[\w\[\]\d]+):\s+(?P<message>.*)"

def run():
    parser = LogParser(SSH_PATTERN)
    
    with open("logs/sample.log", "r") as f:
        for line in f:
            parsed_data = parser.parse_line(line)
            if parsed_data:
                print("--- YENİ LOG YAKALANDI ---")
                print(parser.to_json(parsed_data))

if __name__ == "__main__":
    run()