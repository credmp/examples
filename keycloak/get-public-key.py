#!/usr/bin/env python3

import requests
import json

def convert_public_key(text):
    line_length = 64
    lines = []
    for i in range(0, len(text), line_length):
        lines.append(text[i:i+line_length] + '\n')
    return  '-----BEGIN PUBLIC KEY-----\n' + \
            ''.join(lines) + \
            '-----END PUBLIC KEY-----\n'

REALM_URL='http://localhost:8080/realms/novi-apps'
response = requests.get(REALM_URL)
data = json.loads(response.content.decode('utf-8'))
print(convert_public_key(data['public_key']))
