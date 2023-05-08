import re
import sys
import argparse

DEBUG = False

def discoverAll(data):
	match = []
	targets = []
	[ match.append(x) for x in re.finditer(r'\"host\":\"(\w+|[\.\-])+\".\"ip\":\"(\d+|\.)+\"', data, re.IGNORECASE) ]
	for i in set(match):
		targets.append(i.group())
	return targets

def filteringAllData(data):
	filtered_data = []
	for s in data:
		host = s.split(":")[1].split(",")[0].replace("\"","")
		ip = s.split(":")[2].replace("\"","")
		filtered_data.append(host + " : " + ip )
	return set(filtered_data)

def main():
	for i in range(1,len(sys.argv)):
		file_data = open(sys.argv[i], "rb").read()
		target_list = discoverAll(file_data.decode(errors='ignore'))
		if target_list != []:
			filtered_data = filteringAllData(target_list)
			print('[+] Structured data discovered in {0} file'.format(sys.argv[i]))
			print(filtered_data)

if __name__ == '__main__':
	main()
