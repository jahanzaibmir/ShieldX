import sys
import json
from checker import scan_url

def main():
    if len(sys.argv) != 2:
        print(json.dumps({"error": "URL missing"}))
        sys.exit(1)

    url = sys.argv[1]
    result = scan_url(url)
    print(json.dumps(result, indent=2))

if __name__ == "__main__":
    main()
