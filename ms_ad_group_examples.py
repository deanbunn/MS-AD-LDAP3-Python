#!/usr/bin/env python3

from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute, MODIFY_ADD, MODIFY_DELETE
import ldap3
import uuid
import time
import json
import ad_common_tools


#Load AD Config 
ad_config = ad_common_tools.AD_Config_Cst()

# Class for AD Group
class AD_Group_Cst:
	def __init__(self):
		self.objectguid = ""
		self.cn = ""
		self.dn = ""
		self.member = []


# Function Pull AD User DN by User ID
def ad_pull_user_dn_by_userid(rd_AD_SAM):
	
	#Var for return value
	adUsrDN = ""

	#Var for AD Filter
	adFltr = "(&(objectclass=user)(!(objectclass=computer))(sAMAccountName=" + rd_AD_SAM  + "))"

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
                         	attributes = ["distinguishedName"], 
                         	size_limit=0)

		if(ms_ad_conn.entries and len(ms_ad_conn.entries) > 0):
			adUsrDN = str(ms_ad_conn.entries[0].distinguishedName)

		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')

	
	return adUsrDN


# Function Pull AD Group by ObjectGuid (e.g. 7fcb5751-bb65-4035-aa51-230a715faa8a)
def ad_pull_group_by_objectGuid(rd_AD_ObjGuid):
	
	#Initiate Custom AD Group Object
	cstADGrp = AD_Group_Cst()

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
                         	attributes = ["objectGuid","cn","distinguishedName","member"], 
                         	size_limit=0)

		#print(dir(ms_ad_conn.entries[0]))
		
		
		#Check Returned Search Values
		#Added handling for large groups (1500+ members)
		if(ms_ad_conn.entries and len(ms_ad_conn.entries) > 0):
			cstADGrp.cn = str(ms_ad_conn.entries[0].cn)			
			cstADGrp.dn = str(ms_ad_conn.entries[0].distinguishedName)
			cstADGrp.objectguid = str(ms_ad_conn.entries[0].objectGuid)
			
			if(ms_ad_conn.entries[0]['member']):
				
				if(len(ms_ad_conn.entries[0].member) > 0):
					cstADGrp.member = ms_ad_conn.entries[0].member

					
			elif(ms_ad_conn.entries[0]['member;range=0-1499']):
				
				#Vars for Pull Increments
				grpPullIncr = 1000
				grpPullFrom = 0
				grpPullCont = True

				while(grpPullCont == True):
				        	
					#Set Group Pull To Count
					grpPullTo = grpPullFrom + grpPullIncr -1
					
					#Var for Member Attribute
					grpPullAttrb = "member;range=" + str(grpPullFrom) + "-" + str(grpPullTo)

					#Var for Member Returned Attribute Name
					grpPullRtnAttb = ""
					
					#Set Cont False Before Continuing 
					grpPullCont = False
					
					#Search to Pull Next Range of Group Members
					ms_ad_conn.search(search_base=ad_config.Path_Root,
							  search_filter=adFltr,
							  search_scope=SUBTREE,
							  attributes = [grpPullAttrb],
							  size_limit=0)


					#Check for Returned Entries
					if(ms_ad_conn.entries):
						
						#Check for Member Returned Attribute
						for adSrcAttb in dir(ms_ad_conn.entries[0]):
							
							#Check for Member Attribute
							if(str(adSrcAttb).startswith('member;range')):
								
								#Set Returned Member Attribute Name
								grpPullRtnAttb = str(adSrcAttb)

					
								if(len(ms_ad_conn.entries[0][grpPullRtnAttb]) > 0):
									
									for adGrpMbr in ms_ad_conn.entries[0][grpPullRtnAttb]:
										cstADGrp.member.append(adGrpMbr)

					
								
								if(grpPullRtnAttb.endswith("-*") == False):
									grpPullCont = True	
							
					

					
					
					#Increment Pull From Value
					grpPullFrom += grpPullIncr

					
				
		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')


	return cstADGrp



# Function Display All Nested Members of Group 
def ad_display_nested_members_by_grp_dn(rd_AD_Grp_DN):
	

	#Var for AD Filter
	adFltr = "(&(objectClass=user)(sAMAccountName=*)(memberOf:1.2.840.113556.1.4.1941:=" + rd_AD_Grp_DN + "))"

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
                         	attributes = ["sAMAccountName","distinguishedName"], 
                         	size_limit=0)

		#print(ms_ad_conn.entries)
		if(ms_ad_conn.entries and len(ms_ad_conn.entries) > 0):
			
			print("Members (including nested):")
			print(" ")
			
			for nstMbr in ms_ad_conn.entries:
				print(nstMbr.distinguishedName)		


			print(" ")
				
		#Unbind connection to AD
		ms_ad_conn.unbind()

	else:
		print('no go at this station')



print(" ")
print("Pulling Group Information")

# Get AD Group and Membership
cstADGroup = ad_pull_group_by_objectGuid("407f5264-9564-485f-8c83-7214afed1099")

print(" ")
print("cn: " + cstADGroup.cn)
print("distringuishedName: " + cstADGroup.dn)
print("objectGuid: " + cstADGroup.objectguid)
print("member:")
for grpMbr in cstADGroup.member:
	print(grpMbr)

print(" ")
print("Total member count: " + str(len(cstADGroup.member)))

print(" ")
print("Retrieving user accounts to add or remove from group")
print(" ")

# Get AD User1's DN
adUsr1_dn = ad_pull_user_dn_by_userid("exmp_user1")
print(adUsr1_dn)

# Get AD User2's DN
adUsr2_dn = ad_pull_user_dn_by_userid("exmp_user2")
print(adUsr2_dn)

# Get AD User3's DN
adUsr3_dn = ad_pull_user_dn_by_userid("exmp_user3")
print(adUsr3_dn)

print(" ")
print("Making group membership changes")
print(" ")

# Connect to AD and Modify the Group Membership
ms_ad_server2 = Server(ad_config.DC_Child, get_info=ALL)
ms_ad_conn2 = Connection(ms_ad_server2, user=ad_config.AD_Accnt, password=ad_config.AD_Pwd, authentication=NTLM)
ms_ad_conn2.bind()

# Add User1 and User3 to the Group
ms_ad_conn2.modify(cstADGroup.dn,{'member': [(MODIFY_ADD,[adUsr1_dn,adUsr3_dn])]})

# Remove User2 from the Group
ms_ad_conn2.modify(cstADGroup.dn,{'member': [(MODIFY_DELETE,[adUsr2_dn])]})

# Close Connection to AD
ms_ad_conn2.unbind()

print(" ")
print("Waiting 1 minute for changes to register in Active Directory")
print(" ")
time.sleep(60.0)

# Get AD Group and Membership After Changes
cstADGroupAfter = ad_pull_group_by_objectGuid("407f5264-9564-485f-8c83-7214afed1099")

print(" ")
print("cn: " + cstADGroupAfter.cn)
print("member:")
for grpMbrAft in cstADGroupAfter.member:
	print(grpMbrAft)

print(" ")
print("Total member count after: " + str(len(cstADGroupAfter.member)))
print(" ")
print(" ")

print("Pulling Nested Member Information")
print(" ")
ad_display_nested_members_by_grp_dn(cstADGroupAfter.dn)





