#!/usr/bin/env python3

from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute
import ldap3
import uuid
import sys
import ad_common_tools


# Load AD Config
ad_config = ad_common_tools.AD_Config_Cst()


# Function for Pull AD Object by ObjectGuid (e.g. 7fcb5751-bb65-4035-aa51-230a715faa8a)
def ad_search_by_objectGuid(rd_AD_ObjGuid):
	
	#Var for AD Filter
	adFltr = "(objectGuid=" + ad_common_tools.ad_endian_srch_format(rd_AD_ObjGuid) + ")"

	# AD Server (using global catalog server. If not then remove port assignment)
	ms_ad_server = Server(ad_config.DC_Root, port=3268, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD Global Catalog Server for ObjectGuid
		ms_ad_conn.search(search_base=ad_config.Path_Root, 
                         	search_filter=adFltr, 
                         	search_scope=SUBTREE, 
                         	attributes = [ALL_ATTRIBUTES], 
                         	size_limit=0)

		print(ms_ad_conn.entries)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')


# Function for Searching for Users by Common Name
def ad_search_by_common_name(rd_AD_CommonName):

	#Var for AD Filter
	adFltr = "(&(objectclass=user)(cn=" + rd_AD_CommonName  + "*))"

	# AD Server
	ms_ad_server = Server(ad_config.DC_Root, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD
		ms_ad_conn.search(search_base=ad_config.Path_Root, 
                         	search_filter=adFltr, 
                         	search_scope=SUBTREE, 
                         	attributes = ["objectGuid",
					      "sAMAccountName",
 					       "displayName",
					       "userPrincipalName",
					       "givenName",
					       "sn",
					       "mail"], 
                         	size_limit=0)

		print(ms_ad_conn.entries)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')


# Function for Searching for Users by User ID
def ad_search_by_user_id(rd_AD_SAM):

	#Var for AD Filter
	adFltr = "(&(objectclass=user)(sAMAccountName=" + rd_AD_SAM  + "))"

	# AD Server
	ms_ad_server = Server(ad_config.DC_Root, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD 
		ms_ad_conn.search(search_base=ad_config.Path_Root, 
                         	search_filter=adFltr, 
                         	search_scope=SUBTREE, 
                         	attributes = ["objectGuid",
					      "sAMAccountName",
 					       "memberOf",
 					       "displayName",
					       "userPrincipalName",
					       "proxyAddresses",
					       "givenName",
					       "sn",
					       "pwdlastset",
					       "userAccountControl",
					       "mail",
					       "distinguishedName"], 
                         	size_limit=0)

		print(ms_ad_conn.entries)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')



# Function for Searching for Groups by Common Name
def ad_search_for_groups_by_name(rd_AD_Group_Name):

	#Var for AD Filter
	adFltr = "(&(objectclass=group)(cn=" + rd_AD_Group_Name  + "*))"

	# AD Server
	ms_ad_server = Server(ad_config.DC_Child, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD 
		ms_ad_conn.search(search_base=ad_config.Path_Child, 
                         	search_filter=adFltr, 
                         	search_scope=SUBTREE, 
                         	attributes = ["objectGuid",
 					       "cn",
 					       "displayName",
					       "mail"], 
                         	size_limit=0)

		print(ms_ad_conn.entries)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')


# Function for Searching for Computers by Name
def ad_search_for_computers_by_name(rd_AD_Computer_Name):

	#Var for AD Filter
	adFltr = "(&(objectclass=computer)(cn=" + rd_AD_Computer_Name  + "*))"

	# AD Server
	ms_ad_server = Server(ad_config.DC_Child, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD 
		ms_ad_conn.search(search_base=ad_config.Path_Child, 
                         	search_filter=adFltr, 
                         	search_scope=SUBTREE, 
                         	attributes = ["objectGuid",
 					       "cn",
 					       "operatingSystem",
					       "operatingSystemServicePack",
					       "canonicalName",
					       "whenCreated"], 
                         	size_limit=0)

		print(ms_ad_conn.entries)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')



# Check for Passed in Script Arguments
if(len(sys.argv) > 1):

	#Var for Argument 1
	arg1 = sys.argv[1].lower()

	#Var for Argument 2 (The Search Term)
	arg2 = " "

	#Check for Argument 2
	if(len(sys.argv) > 2):
		arg2 = sys.argv[2]
		
		# Check for Search By Object 
		if(arg1 == "object"):
			ad_search_by_objectGuid(arg2)
		
		# Check for Search By CommonName
		elif(arg1 == "common"):
			ad_search_by_common_name(arg2)

		elif(arg1 == "sam"):
			ad_search_by_user_id(arg2)

		elif(arg1 == "groups"):
			ad_search_for_groups_by_name(arg2)
		
		elif(arg1 == "computers"):
			ad_search_for_computers_by_name(arg2)
			


	else:
		print("What are we searching for?")

else:

	print("What are we doing?")




