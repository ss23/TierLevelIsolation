# TierLevelIsolation
Active Directory Tier Level Model implementation based on Kerberos Authentication Polices. This solution provides a automated Tier level management for Tier 0 and Tier1
## Installation


## configuration file parameters
The follwing configuration parameters are available: 
### Tier0ComputerPath:
Is a array of distinguished names where the Tier 0 computer objects are stored. If a relative distinguished name is used like "OU=Computers,OU=Tier 0,OU=Admin". The computer management script searches for all computer object in this path in every domain defined in the domain list

### Tier1ComputerPath": 
Is a array of distinguished names where the Tier 1 computer objects are stored. If a relative distinguished name is used like "OU=Computers,OU=Tier 1,OU=Admin". The computer managemdn script searches for all computer objects in this path in every domain defined in the domain list

### Tier 0 Computers:
is the SAMAccount name of the Tier 0 computers group. This group should be a universal group in the forest

### Tier1ComputerGroup
is the SAMAccount name of the Tier 1 computers group. This group should be a universal group in the forest

### Tier0UsersPath:
Is a array of distinguished names where the Tier 0 user objects are stored. If a relative distinguished name is used like "OU=Users,OU=Tier 1,OU=Admin". The user management script searches for all users in this path in every domain defined in the domain list

### Tier1UsersPath"
Is a array of distinguished names where the Tier 1 user objects are stored. If a relative distinguished name is used like "OU=Users,OU=Tier 1,OU=Admin". The user management script searches for all users in this path in every domain defined in the domain list

### scope
This paramter defines the scope of the Tier Level Isolation. Valid values are:
#### Tier-0
This value is used for Tier-0 users isolation only
#### Tier-1
This value is used for Tier-1 users isolation only
#### All-Tiers
This vlaue is used if Tier-0 and Tier-1 will be protected by Tier Level Isolation
### ProtectedUsers"
if a array of Tier levels where the users will be added to the protected users group in their domain
#### Tier-0
Tier-0 users will be added to the protected users group
#### Tier-1
Tier-1 users will be added to the protected users group
### PrivilegedGroupsCleanUp
if this parameter is true Tier-0 users will be removed from privileged Active Directory groups 

## Schedule task
### Tier Level Computer Management
...
### Tier Level User Management
...