SharePoint Online Scripts

Export-ADGroupsToAzureAD.ps1  
If you need to migrate groups and group memberships from Active Directory to Azure AD where you don't have AD Connect in place, you can use this script. It will:  
* Prompt you to connect to Azure AD with the Azure AD Powershell module  
* Enumerate AD groups from the selected OU  
* Enumerate all AD accounts from each group, including nested users  
* Create corresponding groups in Azure AD if they don't already exist  
* Create missing Azure AD User accounts if CreateUser parameter is true  
* Populate the groups with corresponding Azure AD user accounts  
* Create a SharePoint Migration Tool permissions mapping file 

SPMTHomeDriveToOneDriveImport.pdf  
Procedure and scripts to create SPMT mapping file to migrate home drives to OneDrive 