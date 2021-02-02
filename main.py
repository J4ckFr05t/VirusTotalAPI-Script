from __future__ import print_function
from virus_total_apis import PublicApi as VirusTotalPublicApi
import json
import time
import hashlib
import urllib
from urllib import request

#Malicious Hash : 10699ac57f1cf851ae144ebce42fa587

apiKey = '1bd77df1a5fc990ab37a419841880aaf32a2c324b43b61e0b23e3a37936553fe'
filePath = '/home/bennet/Downloads/malware.exe'
hashValueMD5 = ''
hashValueSHA1 = ''

class OSINT:

	def hashFunction(self):	
	
		global hashValueMD5
		global hashValueSHA1

		print('\nFile Path        : ', filePath,'\n')
		time.sleep(.5)		
		
		hashValueMD5 = hashlib.md5()	
		hashValueSHA1 = hashlib.sha1()
		
		with open(filePath,'rb') as f:
			for block in iter(lambda: f.read(8192), b''):
				hashValueMD5.update(block)				
				hashValueSHA1.update(block)

		hashValueMD5 = hashValueMD5.hexdigest()
		hashValueSHA1 = hashValueSHA1.hexdigest()

		print('Hash Value MD5   : ', hashValueMD5)
		print('Hash Value SHA1  : ', hashValueSHA1)
	


	def testConnection(self):
		try : 
			urllib.request.urlopen('https://www.google.com/', timeout=5)
			return True
		except Exception as e :
			return False


	def apiFunction(self):
		global hashValueMD5
		global apiKey

		vt = VirusTotalPublicApi(apiKey)
		response = vt.get_file_report(hashValueMD5)
		
		

		if response['response_code'] == 200:
			results = response['results']

			print(response['response_code'])

			if results['response_code'] == 1:
				
				if results['sha1'] != hashValueSHA1:
					return -1
				
				print('Response Code  : ', results['response_code'])
				print(results['verbose_msg'])
				print('\nTotal Engines Scaned : ', results['total'])
				print('Engines Detetcted    : ', results['positives'])
				
				if results['positives'] > 0:
					return 1
				elif results['positives'] == 0:
					return 0
			else:
				print('Response Code : ', results['response_code'])
				print('Error : ', results['verbose_msg'])
				return -1
		
		else:
			print(response['response_code'])
			print(response['error'])
			return -1


	
if __name__ == "__main__": 

	osint = OSINT()
	osint.hashFunction()
	if osint.testConnection() == True:
		print('\nNetwork Status :  Connected\n')
		time.sleep(.5)
		osint_result = osint.apiFunction()
		
		if osint_result == 1:
			print('\nThe file is suspected to be malicious.')
		elif osint_result == 0:
			print('\nThe file is not malicious.')
		elif osint_result == -1:
			print('\nOSINT has failed.')
	else:
		print('\nNetwork Status :  No Internet Connection Found')