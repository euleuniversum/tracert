# -*- coding: utf-8 -*-
import subprocess
import argparse
import socket
import re
import urllib.request
import json
import sys

def start(host):
	ip = ""
	dimain = ""
	if check_host_name_correct(host):
		ip, domain = get_ip_and_domain_values(host);
	if domain:
		print(f"Трассировка АС до {domain} [ {ip} ]:")
	else: 
		print(f"Трассировка АС до {ip}:")
		
	print_as_table(ip);
	
	
def check_host_name_correct(host):
	try:
		if not re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host):
			try:
				socket.gethostbyname(host)
			except socket.gaierror:
				print("Домен введен некорректно")
				sys.exit(1)
		return True
	except ValueError as e:
		print("IP-адресс введен некорректно")
		sys.exit(1)
		
def get_ip_and_domain_values(host):
	if len(re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", host)) == 0:
		ip = socket.gethostbyname(host)
		domain = host
		return [ip, domain]
	else: 
		ip = host
		return [ip, False]

def print_as_table(ip):
	print ('{:>3}'.format("№") + '{:>19}'.format("IP") + '{:>9}'.format("AS") +\
		'{:>11}'.format("Country") + '{:>20}'.format("Provider"))
	try:			 
		for number, ip in parse_ip_tracert(ip):
			print(get_table_row(number, ip))
	except ValueError as e:
		print(e)

def parse_ip_tracert(ip):
	p = subprocess.Popen(['tracert', ip], stdout=subprocess.PIPE)
	number = 0
	while True:
		line = p.stdout.readline()
		if not line:
			break
		line = line.decode("866")
		
		if "Заданный узел недоступен" in line:
			raise ValueError("Отсутствует подключение к интернету")
		elif "Ошибка передачи" in line:
			raise ValueError("Ошибка передачи данных.")

		if len(re.findall(r'\*\*\*', line)) == 0:
			next_ip = re.findall(r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}", line)
			if len(next_ip) != 0:
				if number > 0:
					yield number, next_ip[0]
					number += 1
				else:
					number += 1
		else:
			break


def get_table_row(number, ip):
	try:
		response = urllib.request.urlopen(f'http://ipinfo.io/{ip}/json')
		data = json.loads(response.read())
		
		if 'bogon' in data.keys():
			return '{:>3}'.format(number) + '    {:>15}'.format(ip)
		elif 'error' in data.keys():
			return ValueError(data['error']['message'])
		
		as_name, country, provider = get_as_country_and_provaider(data)
	
		return '{:>3}'.format(number) + '    {:>15}'.format(ip) + '    {:>5}'.format(as_name) +\
                '    {:>3}'.format(country) + '    {:>20}'.format(provider)
	except urllib.error.HTTPError:
		return "IP-адресс введен некорректно"

def get_as_country_and_provaider(data):
	as_name = ""
	country = ""
	provider = ""	
	
	if 'country' in data.keys():
		country = data['country']
	if 'org' in data.keys():
		as_and_provider = re.split(r' ', data['org'], maxsplit=1)
		
		if len(as_and_provider) == 2:
			as_name = as_and_provider[0][2:]
			provider = as_and_provider[1]
		elif len(as_and_provider) == 1 and as_and_provider[0][:2] == "AS":
			as_name = as_and_provider[0]
		else:
			provider = as_and_provider[0]
			
	return as_name, country, provider

def createParser():
	parser = argparse.ArgumentParser()
	parser.add_argument("host", 
						help="IP или доменное имя")
	return parser
	
if __name__ == "__main__":
	namespase = createParser().parse_args(sys.argv[1:])
	start(namespase.host)
	