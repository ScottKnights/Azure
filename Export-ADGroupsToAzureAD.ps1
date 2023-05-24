#Requires -Version 5
#Requires -Modules azuread,activedirectory
 
<#
    .SYNOPSIS
    Create & Populate Selected AD Groups in Azure AD
    .DESCRIPTION
    If you need to migrate groups and group memberships from Active Directory to Azure AD where you don't have AD Connect in place, you can use this script. It will:
        Prompt you to connect to Azure AD with the Azure AD Powershell module
        Enumerate AD groups from the selected OU
        Enumerate all AD accounts from each group, including nested users
        Create corresponding groups in Azure AD if they don't already exist
        Create missing Azure AD User accounts if CreateUser switch is specified
            Users will be created with a 26 character random password. Reset before logon.
        Populate the groups with corresponding Azure AD user accounts
        Create a SharePoint Migration Tool permissions mapping file
 
        If the CreateUser switch is specified, the UPN for creating missing accounts in Azure will be set using the following methods:
            Default is to use the UPN from the AD account
            If UseEMailAddressForUPN switch is selected the email address from the AD account will be used instead
            If the domain from the AD UPN/Email address does not exist in the tenant OR if the OverrideUPNDomain switch is specified
                The domain specified with the UPNDomain parameter will be used, appended to the samAccountName (samAccountName@UPNDomain)
                If no domain is specified in the UPNDomain parameter, the default domain for the tenant will be used
 
    .PARAMETER RootOU
    Mandatory String. Organisational Unit containing the groups you want to migrate.
    .PARAMETER LogFile
    String. Path to log file. Default is .\Export-ADGroupsToAzureAD.log.
    .PARAMETER MappingFile
    String. Path to SPMT permissions mapping file. Default is .\SPMT-Mapping.csv.
    .PARAMETER CreateUser
    Switch. Create group member users which exist in AD but are missing in Azure AD.
    .PARAMETER UseEMailAddressForUPN
    Switch. Use the AD Account EMail address for Azure UPN instead of AD UPN
    .PARAMETER UPNDomain
    String. Domain used to create user UPN in Azure AD if UPN not found in AD. If not specified, tenant default domain is used.
    .PARAMETER OverrideUPNDomain
    Switch. Always use the UPNDomain to create Azure AD UPN instead of the UPN from AD
    .INPUTS
 
    .OUTPUTS
 
    .NOTES
    Author: Scott Knights
    Version:    1.20230222.1 - Initial release
 
    Version:    1.20230223.1 - Added extra options for configuring UPN when creating users
 
    .EXAMPLE
    Export-ADGroupsToAzureAD.ps1 -RootOU "OU=Groups,DC=Domain,DC=com"
    Description:
        Enumerate groups in OU "OU=Groups,DC=Domain,DC=com"
        Enumerate all members of each group, including nested group members
        Do not create AD group member users that don't exist in Azure AD
        Create default log file .\Export-ADGroupsToAzureAD.log
        Create default SPMT mapping file .\SPMT-Mapping.csv
 
    .EXAMPLE
    Export-ADGroupsToAzureAD.ps1 -RootOU "OU=Groups,DC=Domain,DC=com" -CreateUser -LogFile "C:\Temp\MyLog.TXT" -MappingFile "C:\Temp\MyMappingFile.csv"
    Description:
        Enumerate groups in OU "OU=Groups,DC=Domain,DC=com"
        Enumerate all members of each group, including nested group members
        Create AD group member users that don't exist in Azure AD using AD UPN as Azure UPN
            Use the Azure tenant default domain for the UPN of any users with AD UPN domain that doesn't exist in Azure
        Create log file C:\Temp\MyLog.TXT
        Create SPMT mapping file C:\Temp\MyMappingFile.csv
 
    .EXAMPLE
    Export-ADGroupsToAzureAD.ps1 -RootOU "OU=Groups,DC=Domain,DC=com" -CreateUser -UseEMailAddressForUPN -UPNDomain "mydomain.com"
    Description:
        Enumerate groups in OU "OU=Groups,DC=Domain,DC=com"
        Enumerate all members of each group, including nested group members
        Create AD group member users that don't exist in Azure AD using AD Email Address as Azure UPN
            Use the domain "mydomain.com" for the UPN of any users with AD Email address domain that doesn't exist in Azure
        Create default log file .\Export-ADGroupsToAzureAD.log
        Create default SPMT mapping file .\SPMT-Mapping.csv
 
    .EXAMPLE
    Export-ADGroupsToAzureAD.ps1 -RootOU "OU=Groups,DC=Domain,DC=com" -CreateUser -OverrideUPNDomain -UPNDomain "mydomain.com"
    Description:
        Enumerate groups in OU "OU=Groups,DC=Domain,DC=com"
        Enumerate all members of each group, including nested group members
        Create AD group member users that don't exist in Azure AD using "samaccountname@mydomain.com" as the Azure UPN
        Create default log file .\Export-ADGroupsToAzureAD.log
        Create default SPMT mapping file .\SPMT-Mapping.csv#>
 
# ============================================================================
#region Parameters
# ============================================================================
Param(
    [Parameter(Mandatory=$true,Position=0)]
    [String]$RootOU,
 
    [Parameter()]
    [String]$MappingFile=".\SPMT-Mapping.csv",
 
    [Parameter()]
    [string]$LogFile=".\Export-ADGroupsToAzureAD.log",
 
    [Parameter()]
    [string]$UPNDomain,
 
    [Parameter()]
    [switch]$OverrideUPNDomain,
 
    [Parameter()]
    [switch]$UseEMailAddressForUPN,
 
    [Parameter()]
    [switch]$CreateUser
)
#endregion Parameters
 
# ============================================================================
#region Functions
# ============================================================================
# Function to write input object to screen and log file.
Function Out-Log {
    param ( [Parameter(ValueFromPipeline = $true)]
        [PSCustomObject[]]
        $iobjects
    )
 
    process {
        foreach ($iobject in $iobjects)
            {
            $iobject|add-content $logfile -passthru |Write-Output
            }
    }
}
 
# Function to create a random password
Function Get-RandomPassword {
<#
    .SYNOPSIS
        Generate a random password. Default length is 26 characters. Maximum length is 128 characters.
    .EXAMPLE
            New-RandomPassword -length 40
        Generate a 40 character long random password.
#>
    param(
        [Parameter()]
        [int]$PasswordLength = 26
    )
    if ($passwordLength -gt 128) {
        [int]$PasswordLength=128
    }
    Add-Type -AssemblyName 'System.Web'
    $password = [System.Web.Security.Membership]::GeneratePassword($passwordlength,1)
    $password
}
 
#endregion Functions
 
# ============================================================================
#region Execute
# ============================================================================
 
$Start=Get-Date
try {
    Set-Content -LiteralPath $LogFile -Value "Start run at $start" -erroraction stop
} catch {
    Write-Output "Cannot create log file $LogFile. Check path and permissions. Exiting."
    Return
}
 
# Test if Root OU is valid
try {
    Get-ADOrganizationalUnit $rootou -ErrorAction SilentlyContinue
} catch {
    "Organizational Unit $RootOU is invalid. Exiting"|Out-Log
    Return
}
 
# Connect to Azure AD
"Connect to Azure AD"|Out-Log
try {
    Connect-AzureAD -ErrorAction SilentlyContinue
} catch {
    "Not connected to AzureAD. Exiting."|Out-Log
    Return
}
 
"You are connected to the following Azure AD tenant:"|out-log
Get-AzureADTenantDetail|out-log
 
$TenantDomains=Get-AzureADDomain
 
# Check the requested UPNDomain is valid
if ($UPNDomain) {
    if (-not ($TenantDomains.name -contains $UPNDomain)) {
        "UPNDomain $UPNDomain is not valid. These are all domains in your tenant:"|Out-Log
        $TenantDomains.name|Out-Log
        Disconnect-AzureAD
        Return
    }
}
 
# Get the tenant primary domain if UPNDomain is not specified
if (-not $UPNDomain) {
    $UPNDomain=((Get-AzureADTenantDetail).verifieddomains |Where-Object {$_._default -eq $true}).name
}
 
# Delete the SPMT mapping file if it already exists
if (Test-Path -literalpath $MappingFile) {
    Remove-Item -literalpath $MappingFile -Force
}
 
# Get Groups
$Groups=Get-ADGroup -filter * -searchbase $RootOU
 
ForEach ($Group in $Groups) {
    [string]$GroupSID=$Group.sid.value
    [string]$GroupName=$Group.samaccountname
    [string]$DisplayName=$Group.name
    [string]$MailNick=$Groupname.replace(' ','').replace('!','').replace('.','')
 
    # Append Group to SPMT mapping file
    "$GroupSID,$GroupName,TRUE"|out-file -filepath $MappingFile -append
 
    # Check if matching AzureAD Group exists
    $GroupObjectID=$null
    $GroupObjectID=(Get-AzureADGroup -SearchString $GroupName).objectid
    # If cannot find Group, try again without spaces
    if (-not $GroupObjectID) {
            $AltGroup=$GroupName.replace(' ','')
            $GroupObjectID=(Get-AzureADGroup -SearchString $AltGroup).objectid
    }
 
    # Try alternate method to find Group
    if ($GroupObjectID.count -ne 1) {
        $GroupObjectID=(Get-AzureADGroup -Filter "displayname eq '$GroupName'").objectid
            if (-not $GroupObjectID) {
                $GroupObjectID=(Get-AzureADGroup -Filter "displayname eq '$AltGroup'").objectid
            }
    }
 
    # Group ObjectID not unique, skip group
    if ($GroupObjectID.count -gt 1) {
        "Group name $Group returned more than one ObjectID"| out-log
        Continue
    }
 
    # AzureAD Group does not exist. Create the Group
    if ($GroupObjectID) {
        "Azure AD Group $DisplayName already exists"|Out-Log
    } else {
        "Creating Azure AD Group $DisplayName"|Out-Log
        $NewGroup=New-AzureADGroup -Description $GroupName -Displayname $DisplayName -MailEnabled $false -SecurityEnabled $true -MailNickName $MailNick
        $GroupObjectID=$NewGroup.ObjectID
    }
 
    $Users=Get-ADGroupMember $GroupName -recursive
    ForEach ($User in $Users) {
            # Only process AD enabled Users
        $ADUser=get-adUser $User -properties EmailAddress
            if (($ADUser).enabled) {
            [string]$UserName=$ADUser.samaccountname
            $UserObjectID=(Get-AzureADUser -SearchString $UserName).objectid
                # If cannot find Username, try again substituting a space for .
            if (-not $UserObjectID) {
                    $displayname=$UserName.replace('.',' ')
                    $UserObjectID=(Get-AzureADUser -SearchString $displayname).objectid
            }
 
            # User ObjectID not unique, skip User
            if ($UserObjectID.count -gt 1) {
                    "Username $User returned more than one ObjectID"| out-log
                Continue
            }
 
            if (-not $UserObjectID) {
                    "Could not find an Azure AD User object for $User"| out-log
                if ($CreateUser) {
                    $PasswordProfile = New-Object -TypeName Microsoft.Open.AzureAD.Model.PasswordProfile
                    $PasswordProfile.Password = Get-RandomPassword
                    # Set UPN for Azure AD object. Get UPN from AD object or use email address if the UseEMailAddressForUPN switch is specified
                    if ($UseEMailAddressForUPN) {
                        [string]$UserUPN=$ADUser.EmailAddress.tolower()
                    } else {
                        [string]$UserUPN=$ADUser.UserPrincipalName.tolower()
                    }
                    [string]$UserGUID=$ADUser.ObjectGUID
                    [string]$immutableID=[Convert]::ToBase64String([guid]::New($UserGUID).ToByteArray())
                    [string]$UserMailNick=$UserName.replace(' ','').replace('!','')
                    # If OverrideUPNDomain is specified or if the UPN doesn't match a valid Azure domain, derive a UPN from SAM account name & tenant primary domain
                    if ($OverrideUPNDomain -or (-not ($TenantDomains.name -contains $UserUPN.split("@")[1]))) {
                        [string]$UserUPN=($username+"@"+$UPNDomain).tolower()
                    }
                    "CreateUser is true. Creating Azure AD user $UserName"|Out-Log
                    Try {
                        $NewAzureUser=New-AzureADUser -DisplayName $UserName -PasswordProfile $PasswordProfile -UserPrincipalName $UserUPN -AccountEnabled $true -MailNickName $UserMailNick -ImmutableId $immutableID
                        $UserObjectID=$NewAzureUser.ObjectId
                    } catch {
                        "Unable to create Azure AD User $UserName."|Out-Log
                        Continue
                    }
                } else {
                    Continue
                }
            }
 
            # If unique User and Group found, add the User to the Group
            "Adding $User ($UserObjectID) To $Group ($GroupObjectID)"|out-log
            Try {
                Add-AzureADGroupMember -ObjectId $GroupObjectID -RefObjectId $UserObjectID
            } Catch {
                "Unable to add $User to $Group. May already be a member."|Out-Log
            }
            }
    }
}
 
# Disconnect from Azure AD
Disconnect-AzureAD
 
#endregion Execute