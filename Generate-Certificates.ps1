<#

	This script is provided to illustrate how to use the Update-Certificate-Http command
	The example will not successfully generate a certificate because the domains used are 
	intended to be fictitious.  You will need to modify the command line to reference your
	own domains.

 #>

# Create a suffix that changes regularly
$suffix = "-{0:D2}-{1:D2}-{2:D2}" -f [int](Get-Date).year,[int](Get-Date).month,[int](Get-Date).day

# Load the function for ACMEScript
. .\Update-Certificate-Http.ps1

# Call the function to create/update a certificate for a single domain
# NOTE: Remove the 'checkParameters' option when you are ready to generate a certificate.
# Check parameters allows you see verify your parameters are valid before you try to generate.
Update-Certificate-Http -alias "myalias$suffix" -domain "www.mydomain.com" -websiteName "Default Web Site" -checkParameters

# Line below shows how add multiple domains to a single certificate so just one can be used to validate multiple sites
# Update-Certificate-Http -alias "myalias$suffix" -domain "www.mydomain.com" -websiteName "Default Web Site" -domains @{ "otheralias$suffix"="www.myotherdomain.com";"anotherdomainalias$suffix"="www.anotherdomain.com" } -Email "letsencrypt@mydomain.com" -Organization "My Org Name" # -checkParameters

