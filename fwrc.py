#!/usr/bin/python
# PrettyTable Line Format from https://stackoverflow.com/users/297570/rolandog

'''
         Python OSINTpa
'''
import os.path
import ConfigParser
import argparse
import sys
import re
import prettytable

from termcolor import colored, cprint
from prettytable import ALL as ALL

NAME = 'fwRC'
VERSION = '1.0(0)'
BANNER = r"""
_____________      _____________________  
\_   _____/  \    /  \______   \_   ___ \ 
 |    __) \   \/\/   /|       _/    \  \/ 
 |     \   \        / |    |   \     \____
 \___  /    \__/\  /  |____|_  /\______  /
     \/          \/          \/        \/ 
                                        %s
""" % VERSION


output = {}

def check_file(value):
        if (os.path.isfile(value)):
                return value
        else:
                raise argparse.ArgumentTypeError('Can\'t read config file: %s' % value)

def check_firewall_type(info):
	m = re.search('[#|!]RANCID-CONTENT-TYPE:\s([a-z]+)',info)
	if m:
		return m.group(1)
	else:
		return 'error'

def grabb_fortigate_block(data,block):
	i = 0
	inicio = 0
	fin = 0
	data_lines=data.split('\n')
        for line in data_lines:
                if re.match(block,line) is not None:
                        inicio = i
                        break
                i += 1
        for x in xrange(inicio,len(data_lines)):
                if re.match("end",data_lines[x]) is not None:
                        fin = x
                        break
        data_block=[]
        for x in xrange(inicio,fin):
                data_block.append(data_lines[x])

	if args.debug is not False:
		print "    - Config Block Init: ", colored(str(inicio),'white',attrs=['bold']), " -> Config Block End ", colored(str(fin),'white',attrs=['bold'])
	
        return data_block



def check_firewall_users(data,fwtype,filename):
	data_lines=data.split('\n')
	try:
		username = config.get(fwtype,'username')
		userlist = ""
		count = 0
		if fwtype=="fortigate":
			data_lines=grabb_fortigate_block(data,config.get(fwtype,'username_section'))
		
		for line in data_lines:
			m0 = re.match(username,line) 
			if m0 is not None:
				count +=1
				user = m0.group(1)
				userlist = userlist + " " + user
		output[filename].append(count)
		output[filename].append(userlist)
		if args.debug is not False:
			print "    - ", colored(str(count),'white',attrs=['bold']), " User(s) [ ", colored(str(userlist),'white',attrs=['bold']), " ]"		
	except:
		pass

def count_firewall_acls(data,fwtype,filename):
	data_lines=data.split('\n')
	try:
		acl = config.get(fwtype,'acl')
		count = 0
		for line in data_lines:
			if "$" not in acl:
				if acl in line: count +=1
			else:
				if re.match(acl,line) is not None: count+=1
		output[filename] = [count,fwtype]
		if args.debug is not False:
			print "    - ", colored(str(count),'white',attrs=['bold']), "] Matches of pattern [ ", colored(str(acl),'white',attrs=['bold']), " ] "
	except:
		pass

def check_firewall(config_file,filename):
	with open(config_file,'r') as filedata:
		info = filedata.readline()
        	data = filedata.read()
                count = 0
                for line in data: count += 1
                fwlines = count
		fwtype = check_firewall_type(info)
		if args.debug is not False:
			print "    - ", colored(str(fwtype),'white',attrs=['bold']), " | ", colored(str(fwlines),'white',attrs=['bold']), " Character(s) "
		count_firewall_acls(data,fwtype,filename)
		check_firewall_users(data,fwtype,filename)


def format_users(users, max_line_length):
    #accumulated line length
    ACC_length = 0
    words = users.split(" ")
    formatted_users = ""
    for word in words:
        #if ACC_length + len(word) and a space is <= max_line_length 
        if ACC_length + (len(word) + 1) <= max_line_length:
            #append the word and a space
            formatted_users = formatted_users + word + " "
            #length = length + length of word + length of space
            ACC_length = ACC_length + len(word) + 1
        else:
            #append a line break, then the word and a space
            formatted_users = formatted_users + "\n" + word + " "
            #reset counter of length to the length of a word and a space
            ACC_length = len(word) + 1
    return formatted_users



def show_results(output):
	t = prettytable.PrettyTable(hrules=ALL)
	t.field_names= ['Firewall','Type','No_Acls','No_Users','Users']	
	t.align["No_Acls"] = "r"
	t.align["No_Users"] = "r"
	t.sortby=args.sort
	users = ""
	for key,value in output.iteritems():
		try:
			users=value[2]
		except:
			users='--'
		try:
			userlist=value[3]
		except:
			userlist = "--"
		formatted_users = format_users(userlist,62)
		t.add_row([key,value[1],value[0],users,formatted_users])

	if args.debug is not False:
		print colored('\n\n[+]','green',attrs=['bold']),colored('Printing table of results:\n','green')
	print t

def main():

        # Arguments Parser
        parser = argparse.ArgumentParser(
            description="%s #v%s Firewall Rule Count from RANCID backup data" % (NAME,VERSION)
        )
        parser.add_argument('-c', '--config', help="Specify config file. (Default:config.ini)", required=False, default='./config.ini', type=check_file)
	parser.add_argument('-s', '--sort', help="Sort table results by Column (Firewall, Acls", required=False, default="Firewall", choices=["Firewall","No_Acls","No_Users"])
	parser.add_argument('-d', '--debug', help="Enable debug mode. (Default: False)", required=False, default=False,action="store_true")
	global args
        args = parser.parse_args()


        # Load config file
	global config
	config = ConfigParser.ConfigParser()
        config.read(args.config)

	path = config.get('FWRC','path')
	exceptions = config.get('FWRC','exceptions')
	print colored(BANNER,'yellow')
	for root,dirs,files in os.walk(path):
		for filename in files:
			if filename not in exceptions and not filename.endswith('.new'):
				if args.debug is not False:
					print colored('[+]','green',attrs=['bold']),colored('Gathering information for','green'), colored (filename,'white',attrs=['bold'])
				fullfilename=path+'/'+filename
				check_firewall(fullfilename,filename)

	show_results(output)

if __name__ == "__main__":
        main()
