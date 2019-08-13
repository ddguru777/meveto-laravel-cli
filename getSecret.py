import json
import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA256
from Crypto.Cipher import PKCS1_OAEP
import base64

api_token = ''
api_url_base = 'http://laraveltestproject.com/api/'

headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

def getSecret():
    username = input("Enter your username: ")
    secretName = input("Enter your secretName: ")
    api_url = '{0}getSecret?username={1}&secretName={2}'.format(api_url_base, username, secretName)

    response = requests.get(api_url, headers=headers)

    if response.status_code == 200:
        ret = json.loads(response.content.decode('utf-8'))
        encryptedMessage = ret['success']
        
        fd = open("{0}_private_key.pem".format(username), "rb")
        private_key = fd.read()
        fd.close()
        
        rsa_key = RSA.importKey(private_key)
        ret = rsa_key.decrypt(base64.b64decode(encryptedMessage))
        
        start_pos = ret.decode('latin-1').find('-----start-----')
        end_pos = ret.decode('latin-1').find('-----end-----')
        return ret[start_pos+15:end_pos].decode('utf-8')
    else:
        return None

secret = getSecret()

if secret is not None:
    print('Secret: {0}'.format(secret))
else:
    print('[!] Request Failed')