Example scripts for working with Microsoft Active Directory using Python and the LDAP3 module.

Project Files:

ad_config.json contains the values of the AD account to use when querying, domain controller names, and search paths 

ad_common_tools.py loads configuration and common functions used in all scripts

ms_ad_group_examples.py examples of pulling direct and nested group membership and modifying group membership

ms_ad_search_examples.py some basic queries for user, group, and computer objects


Please note that example environment has user accounts in a parent domain and computer and groups in a child domain.  

It was fun figuring out the AD search filter format for objectGuids in a regular LDAP search and how to handle pulling membership for AD groups with over 1,500 members. 


