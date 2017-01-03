<#
   ACMESharp does not yet support renewing certificates, so every run on a new date issues
   a complete set of new certificates. For this reason it is best to run the script about
   once a month. Otherwise it will exceed the usage caps of Let's Encrypt.
 #>

# ACME Vault to use
$vaultProfile = ""
 
# Create a suffix that changes regularly
$suffix = "-{0:D2}-{1:D2}-{2:D2}" -f [int](Get-Date).year,[int](Get-Date).month,[int](Get-Date).day

# AWS account with ability to create/delete challenge records
$awsProfile = "default"

# VPC zone Id's for the the domains we need
$vpcZoneId = .\cli53 list --profile $awsProfile --format jl | ConvertFrom-Json | Where { $_.Name -eq 'example.com.' } | Select -ExpandProperty Id | %{$_ -Replace '/hostedzone/',''}

# Load the function for ACMEScript
. .\Update-Certificate.ps1

# Update www.example.com certificate and update in IIS
Update-Certificate -alias "www$suffix" -domain "www.example.com" -websiteName "My Website" -VaultProfile $vaultProfile -ChallengeType "dns-01" -ChallengeHandler "awsRoute53" -ChallengeParameters @{HostedZoneId="$vpcZoneId";AwsProfileName="$awsProfile"}

# Update api.example.com certificate (not an IIS website)
Update-Certificate -alias "api$suffix" -domain "api.example.com" -notIIS -VaultProfile $vaultProfile -ChallengeType "dns-01" -ChallengeHandler "awsRoute53" -ChallengeParameters @{HostedZoneId="$vpcZoneId";AwsProfileName="$awsProfile"}

# Restart the api service to load the new certificate
Restart-Service myapi
