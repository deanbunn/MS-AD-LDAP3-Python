#!/usr/bin/env python3

import json
import uuid

# Class for AD Config
class AD_Config_Cst:
	def __init__(self):
		self.AD_Accnt = ""
		self.AD_Pwd = ""
		self.DC_Root = ""
		self.DC_Child = ""
		self.Path_Root = ""
		self.Path_Child = ""
		
		#Load Local AD Config File
		load_ad_config = json.loads(open('ad_config.json').read())
		self.AD_Accnt = load_ad_config['AD_Accnt']
		self.DC_Root = load_ad_config['DC_Root']
		self.DC_Child = load_ad_config['DC_Child']
		self.Path_Root = load_ad_config['Path_Root']
		self.Path_Child = load_ad_config['Path_Child']

		#Load Account Password File (not secure method. just for demo)
		self.AD_Pwd = str((open("ad_account_pwd.txt")).read()).strip().replace("\\n","")



		
# Function for Formating AD ObjectGuid in Little Endian Format for Searches
# (e.g. 7fcb5751-bb65-4035-aa51-230a715faa8a will return \51\57\CB\7F\65\BB\35\40\AA\51\23\0A\71\5F\AA\8A)
def ad_endian_srch_format(rdGuid):

	#Var for Return Value
	fltrGuid = ""

	#Parse into Guid
	wrkGuid = uuid.UUID('{' + rdGuid + '}')

	for wrkByte in wrkGuid.bytes_le:
		fltrGuid += "\\" + "{:02x}".format(wrkByte).upper()

	return fltrGuid




