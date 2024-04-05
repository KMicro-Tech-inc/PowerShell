# Author: Ian D. Hanley | KMicro Tech, Inc | https://kmicro.com
# Description: This script is helpful for smaller deployments on a single domain. It creates a gMSA and grants it the required read privileges for use as a DSA in Defender for Identity

# Step 1: Prompt the user for the domain and a name for the DSA that will be created in step 3:
$domain = Read-Host -Prompt "Please enter the domain"
$gmsaAccountName = Read-Host -Prompt "Please enter the gMSA account name"

# Step 2: Prompt the user for the principals allowed to retrieve the password (principles will be your domain controllers with the MDI sensor installed):
$principals = Read-Host -Prompt "Please enter the principals (separated by a comma)"
$principalsArray = $principals -split ',' | ForEach-Object { $_.Trim() }

# Step 3: Create new gMSA using Read-Host input from above statements:
New-ADServiceAccount -Name "$gmsaAccountName" -DNSHostName "$gmsaAccountName.$domain" -PrincipalsAllowedToRetrieveManagedPassword $principalsArray

# Step 4: Grab distinguished name for Deleted Objects
$distinguishedName = ([adsi]'').distinguishedName.Value
$deletedObjectsDN = "CN=Deleted Objects,$distinguishedName"

# Step 5: Make current user the Owner of Deleted Objects (required for next step)
dsacls.exe "$deletedObjectsDN" /takeOwnership

# Step 6: Assign read permissions for Deleted Objects to DSA account
# This requires current user account to have ownership (see previous command)
dsacls.exe "$deletedObjectsDN" /G "$domain\$gmsaAccountName:LCRP"
