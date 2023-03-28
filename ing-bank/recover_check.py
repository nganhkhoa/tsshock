import json
import requests

exploiter = json.load(open('share0.json', 'r'))
pkx = str(int('0x' + exploiter["public_key"]["x"], 16))
i = "0"

url = "http://localhost:1337/recover-private-key"


response = requests.post(url, json={'pkx': pkx, 'i': i})
if response.status_code == 200:
    print('recovered privatekey', response.text)
