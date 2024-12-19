# Known Event ID
## TierLevelComputerManagement
|EventID |Severity   |Message|
---
|1000| Information   | computermanagemetn script started                                |
|1001| Debug         | Invocation line                                                  |
|1002| Debug         | Reading configuration from AD                                    |
|1003| Error         | Missing AD configuration settings                                |
|1004| Error         | AD Web Service failed to connect                                 |
|1100| Debug         | Reading configuration file from default configuration path       |
|1101| Debug         | Reading configuration from file                                  |
|1200| Error         | Cannot find the Tier 0 computer group                            |
|1201| Debug         | Current count of meber in the Tier 0 computer group              |
|1202| Error         | Can't find Tier 1 comptuer group                                 |
|1203| Error         | AD Web Service failed to connect                                 |
|1300| Warning       | Missing sa Tier 0 computer OU                                    |
|1301| Debug         | Count member in tier 0 group                                     |
|1302| Information   | Adding a computer to Tier 0 computer group                       |
|1303| Debug         | Tier 0 computer group updated                                    |
|1304| Warning       | Removing a computer from Tier 0 computer groups                  |
|1400| Warning       | A Tier 1 OU is missing                                           |
|1401| Information   | A computer is added to ther Tier 1 computer group                |
|1402| Error         | Unexpected error occured whil updating the Tier 1 computer group |
|1403| Warning       | Removing a computer from Tier 1 computer group                   |
---

## TierLevelUserManagement
|EventID|Severity    |Message|
---
|2000   | Information| Script started                                               |
|2001   | Debug      | Invocation line                                              |
|2002   | Error      | Missing Kerberos Authentication Policy                       |
|2003   | Debug      | Failed to read the configuration form the config file        |
|2004   | Error      | configuration File missing                                   |
|2005   | Error      | Cannot read the configuration file                           |
|2006   | Error      | Configurationfile paramter error                             |
|2008   | Debug      | Validating Schema admins                                     |
|2009   | Debug      | Validating Enterprise admins                                 |
|2101   | Error      | Kerberos Authenticatin Policy not found                      |
|2102   | Warning    | OU missing                                                   |
|2103   | Warning    | The Built-In Administrator located in Tier 0 users OU        |
|2104   | Information| A Kerberos Authentication Policy is added to a user          |
|2105   | Information| A user is markedas sensitive and can not be delegated        |
|2106   | Information| A user is added to the protected users group                 |
|2107   | Error      | Access denied while changing user attribute                  |
|2108   | Error      | A AD identitiy not found                                     |
|2109   | Error      | Unexpected Error                                             |
|2200   | Warning    | Missing group SID                                            |
|2201   | Warning    | A user is removed from a privileged group                    |
|2202   | Error      | Cannot connect to AD-Webservice                              |
|2203   | Error      | A error occured while a remvoe a user from a privileged group|
|2204   | Error      | unexpected error                                             |
|2205   | Debug      | privileged service account detected                          | 
|2206   | Debug      | privileged user detected                                     |
|2300   | Error      | Cannot connect to a AD Web Service                           | 
---


