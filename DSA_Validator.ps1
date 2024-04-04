# Author: Ian D. Hanley | Security Architect | KMicro Tech, Inc
# Description: This script prompts for a gMSA used as the Directory Service Account (DSA) for Defender for Identity (MDI)

# Install & import DFI module:
Install-Module DefenderForIdentity
Import-Module DefenderForIdentity
 
Write-Host "`n"
 
# Prompt for gMSA to test:
$identity = Read-Host -Prompt 'Please specify gMSA to test against'
 
Write-Host "`nDoes this gMSA work on this DC (true/false)?" 
Test-ADServiceAccount -Identity $identity
 
Write-Host "`nPrinciples allowed to retrieve the PW for this gMSA?"
(Get-ADServiceAccount -Identity $identity -Properties *).PrincipalsAllowedToRetrieveManagedPassword
 
# Add a new line
Write-Host "`nThe following is applicable only to Directory Service Accounts (DSA):" 
Test-MDIDSA -Identity $identity -Detailed 
