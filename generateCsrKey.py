#!/usr/bin/python3

# author: michael kosko
# date: 27/07/2018
# purpose: generate CSR and key from SUBJECT file with a list of cert subjects

from OpenSSL import crypto, SSL
import subprocess, os, sys

# set present working dir
pwd = os.getcwd()

# set RSA as the crypto type
type_rsa = crypto.TYPE_RSA

#===================================================================================
# generate key file for CSR

def generateKey(keyType, bits, fqdn):
	keyfile = pwd + '/' + fqdn + '.key'
	key = crypto.PKey()
	key.generate_key(keyType, bits)
	if os.path.exists(keyfile):
		print("Key already present, aborting...")
		print(keyfile)
		key = 0
	else:
		with open(keyfile, 'wb') as k:
			k.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
	return key

#===================================================================================
# generate CSR

def generateCsr(csr = [], sans = []):
	C  = csr[0]
	ST = csr[1]
	L  = csr[2]
	O  = csr[3]
	OU = csr[4]
	CN = csr[5]

	csrFile = pwd + '/' + CN + '.csr'

	sansDNS = []
	for i in sans:
		sansDNS.append('DNS: %s' % i)

	sansDNS = ', '.join(sansDNS)

	req = crypto.X509Req()
	req.get_subject().countryName = C
	req.get_subject().stateOrProvinceName = ST
	req.get_subject().localityName = L
	req.get_subject().organizationName = O
	req.get_subject().organizationalUnitName = OU
	req.get_subject().CN = CN

	if sansDNS:
		san_constraint = ([crypto.X509Extension(b"subjectAltName", False, sansDNS.encode())])
		x509_extensions = san_constraint
		req.add_extensions(x509_extensions)

	# generate key file for CSR
	key = generateKey(type_rsa, 2048, CN)

	if key != 0:
		req.set_pubkey(key)
		req.sign(key, "sha256")

	if os.path.exists(csrFile):
		print("CSR already present, aborting...")
		print(csrFile)
	else:
		with open(csrFile, 'wb') as c:
			c.write(crypto.dump_certificate_request(crypto.FILETYPE_PEM, req))

#===================================================================================

# subject file location
subjectFile = pwd + '/SUBJECT'
# subject headings for removal
subjectHeadings = ['C=','ST=','L=','O=','OU=','CN=']

# verify subject file is present and read in data
try:
	with open(subjectFile, 'r') as s:
		subjectList = s.read().splitlines()
except IOError:
	print("SUBJECT file does not exist in " + pwd + ". Please make sure this file is present.")
	sys.exit(1)

# iterate through subject list and parse information for CSR
for i in range(len(subjectList)):
	subjectData = []
	subjectData = subjectList[i].split('/')
	subjectData.remove('')
	for k in range(len(subjectHeadings)):
		if subjectHeadings[k] in subjectData[k]:
			subjectData[k] = subjectData[k].replace(subjectHeadings[k],'')
	# if SANS entries are present separate them from subject data
	if len(subjectData) > 6:
		diff = len(subjectData) - 6
		sans = []
		for n in range(diff):
			sans.append(subjectData.pop())
		print("Processing " + subjectData[5] + "....")
		generateCsr(subjectData,sans)
	else:
		print("Processing " + subjectData[5] + "....")
		generateCsr(subjectData)

exit
