import json
import requests
from Crypto.PublicKey import RSA

#Generate a public/ private key pair using 4096 bits key length (512 bytes)
new_key = RSA.generate(4096, e=65537)

#The private key in PEM format
private_key = new_key.exportKey("PEM")

#The public key in PEM Format
public_key = new_key.publickey().exportKey("PEM")

api_token = ''
api_url_base = 'http://laraveltestproject.com/api/'

headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

def register():
    username = input("Enter your username: ")
    # publicKey = input("Enter your publickey: ")

    data = {'username': username, 'publicKey': public_key}

    api_url = '{0}register'.format(api_url_base)

    response = requests.post(api_url, data=data)

    if response.status_code == 200:
        fd = open("{0}_private_key.pem".format(username), "wb")
        fd.write(private_key)
        fd.close()

        fd = open("{0}_public_key.pem".format(username), "wb")
        fd.write(public_key)
        fd.close()

    return json.loads(response.content.decode('utf-8'))

register = register()

if register is not None:
    print(register)
else:
    print('[!] Request Failed')