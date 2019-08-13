import json
import requests

api_token = ''
api_url_base = 'http://laraveltestproject.com/api/'

headers = {'Content-Type': 'application/json', 'Authorization': 'Bearer {0}'.format(api_token)}

def getServerKey():
	api_url = '{0}getServerKey'.format(api_url_base)

	response = requests.get(api_url, headers=headers)

	#if response.status_code == 200:
	return json.loads(response.content.decode('utf-8'))
	#else:
	#	return None

serverKey = getServerKey()

if serverKey is not None:
	print('ServerKey: {0}'.format(serverKey))
else:
	print('[!] Request Failed')
