Malware Detection using Open Source Intelligence

****Modification :****

1 . Added a function hashFunction() which takes input the filepath of the file that needs
to be scanned. Then using hashlib library the MD5 hash value of the file is generated.

2 . Added a function testConnection() to check if stable internet connection exists.

3 . Modified the function apiFunction() to provide apropriate responses according to the 
response codes returned by the VirusTotal API. 

****Source :****

1 . VirusTotal API Implemetation : https://pypi.org/project/virustotal-api/

2 . VirusTotal API Documentation : https://developers.virustotal.com/reference#api-responses

