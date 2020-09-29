#!/usr/bin/python

#####################################
## Dridex configuration extractor -##
## Copyright (c) 2020              ##
## Written by CESAR VERSATTI       ##
#####################################


import pefile
import itertools
import argparse
from binascii import *
imported_aplib = __import__('aplib')

parser = argparse.ArgumentParser(description='Dridex config extractor')
parser.add_argument('-f', dest='filename', help='Filename of the dridex sample',required=True)
args = parser.parse_args()

pe = pefile.PE(args.filename)
numsec = 0
print '##########################################'
print 'Dridex configuration extractor'
print '##########################################\n'

#pe = pefile.PE('ED9847F3147F21D9825D09D432ECEA3C')
for section in pe.sections:
	#numsec += 1
	print 'Section found: ',section.Name
	xorkey = section.get_data()[:4]
	print 'Trying to de-xor with key: ',hexlify(xorkey)
	data = section.get_data()[12:]
	decrypted =  ''.join(chr(ord(c1) ^ ord(c2)) for c1, c2 in zip(data, itertools.cycle(xorkey)))
	print 'Decrypted raw: ',decrypted[:30],'hex: ',hexlify(decrypted[:30])
	if '<conf' in decrypted:
		print '\n--> Found "conf" in section, trying to decompress (aplib) ...'
		try:
			config_raw = imported_aplib.decompress(decrypted).do()
			print '\n--> ### Success !!! Found correct section: ',section.Name
			print '--> ### RAW configuration: ',config_raw,'\n'
			config = config_raw[0]
			config_start = config.find('<config')
			print '##########################################\n'
			print config[config_start:],'\n'
		except:
			print 'Not able to decompress with aplib ...'
	else:
		print 'Conf not found in decrypted ... continuing ...'
