import json
import requests
from Crypto.PublicKey import RSA
from getServerKey import getServerKey
from Crypto.Cipher import AES
import base64
from Crypto.Random import get_random_bytes
from laravel_encryption import encrypt, decrypt

api_token = ''
api_url_base = 'http://laraveltestproject.com/api/'

headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

def storeSecret():
    username = input("Enter your username: ")
    secretName = input("Enter your secretName: ")
    plainMessage = input("Enter your Message: ")
    
    fd = open("{0}_public_key.pem".format(username), "rb")
    public_key = fd.read()
    fd.close()

    serverKey = getServerKey()
    temp_key = serverKey['success'].replace("base64:", "")
    
    key = base64.b64decode(temp_key)

    encryptedMessage = encrypt(plainMessage, key)

    data = {'username': username, 'secretName': secretName, 'encryptedSecret': encryptedMessage, 'key': public_key}
    api_url = '{0}storeSecret'.format(api_url_base)

    response = requests.post(api_url, data=data)

    return json.loads(response.content.decode('utf-8'))
    
secret = storeSecret()

if secret is not None:
    print('secret: {0}'.format(secret))
else:
    print('[!] Request Failed')
