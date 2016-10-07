#!/usr/bin/env python3

from ldap3 import Server, Connection, SIMPLE, SYNC, ALL, SASL, SUBTREE, NTLM, BASE, ALL_ATTRIBUTES, Entry, Attribute, MODIFY_ADD, MODIFY_DELETE
import ldap3
import uuid
import time

# Load Account Password File (not secure method. just for demo)
flTxADAcnt = open("ad_account_pwd.txt")

# AD Account to use for query calls
adQryAcntUsrID = "domain\\userID"
adQryAcntUsrPwd = str(flTxADAcnt.read()).strip().replace("\\n","")

# AD Servers to query against
# Ideally a Global Catalog Servers. Listed two for ADs with group resources in child domains
adQryServer = "dc1.mycollege.edu"
adQryServer2 = "dc2.engr.mycollege.edu"

# AD Search Base
# Listed two for ADs with resources in child domains.
adQrySrchBase = "DC=MYCOLLEGE,DC=EDU"
adQrySrchBase2 = "DC=ENGR,DC=MYCOLLEGE,DC=EDU"


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
	ms_ad_server = Server(adQryServer, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=adQryAcntUsrID, password=adQryAcntUsrPwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD 
		ms_ad_conn.search(search_base=adQrySrchBase, 
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


# Function Pull AD Group by ObjectGuid (e.g. 7fcb5751-bb65-4035-aa51-230a715faa8a)
def ad_pull_group_by_objectGuid(rd_AD_ObjGuid):
	
	#Initiate Custom AD Group Object
	cstADGrp = AD_Group_Cst()

	#Var for AD Filter
	adFltr = "(objectGuid=" + ad_endian_srch_format(rd_AD_ObjGuid) + ")"

	# AD Server (using global catalog server. If not then remove port assignment)
	ms_ad_server = Server(adQryServer, port=3268, get_info=ALL)

	# AD Connection
	ms_ad_conn = Connection(ms_ad_server, user=adQryAcntUsrID, password=adQryAcntUsrPwd, authentication=NTLM)

	# Connect to AD
	if ms_ad_conn.bind():
		#Search AD Global Catalog Server for ObjectGuid
		ms_ad_conn.search(search_base=adQrySrchBase, 
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
					ms_ad_conn.search(search_base=adQrySrchBase,
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



print(" ")
print("Pulling Group Information")

# Get AD Group and Membership
cstADGroup = ad_pull_group_by_objectGuid("407f5264-9564-485f-8c83-7214afed1099")

print(" ")
print("cn: " + cstADGroup.cn)
print("distringuishedName: " + cstADGroup.dn)
print("objectGuid: " + cstADGroup.objectguid)
print("member:")
print(cstADGroup.member)
print(" ")
print("Total member count: " + str(len(cstADGroup.member)))

print(" ")
print("Retrieving user accounts to add or remove from group")
print(" ")

# Get AD User1's DN
adUsr1_dn = ad_pull_user_dn_by_userid("userid1")
print(adUsr1_dn)

# Get AD User2's DN
adUsr2_dn = ad_pull_user_dn_by_userid("userid2")
print(adUsr2_dn)

# Get AD User3's DN
adUsr3_dn = ad_pull_user_dn_by_userid("userid3")
print(adUsr3_dn)

print(" ")
print("Making group membership changes")
print(" ")

# Connect to AD and Modify the Group Membership
ms_ad_server2 = Server(adQryServer2, get_info=ALL)
ms_ad_conn2 = Connection(ms_ad_server2, user=adQryAcntUsrID, password=adQryAcntUsrPwd, authentication=NTLM)
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
print(cstADGroupAfter.member)
print(" ")
print("Total member count after: " + str(len(cstADGroupAfter.member)))
print(" ")



