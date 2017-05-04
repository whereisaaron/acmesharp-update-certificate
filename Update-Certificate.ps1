<#
.SYNOPSIS
    Create a new or update an existing LetsEncrypt certificate for one or more 
    domains and add it to a store then update the SSL bindings for an IIS web site
.DESCRIPTION
    The script will use ACMESharp to create a new or update an existing
    certificate for a domain.  If generated successfully the script will
    add the certificate to the certificate store and update the SSL binding for a web site.
    This script is for use with IIS
    The script will validate the parameter provided. For example, the web site name must
    be a valid IIS site name, the domain(s) listed must be defined as host headers for 
    the site, there must be an existing https binding (even if it has an invalid certificate)
    and the domain and alias specified must not also appear in the list of alternative names.
.PARAMETER alias
    A unique idenifier for the attempt to create a certificate.
.PARAMETER domain
    The domain for which you want to create a certificate.
.PARAMETER domains
    A hashtable of domains for which you want to create a certificate 
    for example  @{"alias1"="my.domain.com";"alias2"="other.domain.com"}.
    The domains must be defined as host headers in the site given in the 
    webSiteName parameter.
.PARAMETER websiteName
    The name of the web site hosting the domain(s) for which you are generating a certificate.
    LetsEncrypt will verify your attempt to create a certificate by checking for a
    file containing a token provided by LetsEncrypt. This script will create the file relative 
    to the location of the web site you specify in this parameter.
.PARAMETER noCertOverwrite
    Should a newly generated certificate overwrite a previously
    generated certificate for the same alias.
.PARAMETER certFolder
    A temporary location to hold the generated certificate before
    it is imported into the certificate store. (Default Downloads)
.PARAMETER certPath
    The location in the certificate store into which the certificate should 
    be imported. (Default: \LocalMachine\WebHosting)
.PARAMETER location
    The location of this script and the ACMEScript software. (Default: c:\ACMEScript)
    The country (C) to display in the certificate
.PARAMETER Country,
    The state or province (ST) to display in the certificate
.PARAMETER StateOrProvince,
    The organization (O) to display in the certificate
.PARAMETER Organization,
    The the organization unit (OU) to display in the certificate
.PARAMETER OrganizationUnit,
    The Description to display in the certificate
.PARAMETER Description,
    The email address to display in the certificate
.PARAMETER Email,
    Provided if the parameters are to be check but the process not executed
.PARAMETER checkParameters 
    Set this option to true if old certificates for the domain are to be retained (by default they are removed)
.PARAMETER keepOldCertificates
    Use this option if IIS is not to be updated or used for http-01 challenges
.PARAMETER notIIS
    Which ACMESharp vault profile to use, will default to "":user"", or "":system"" if elevated, or \$env:ACMESHARP_VAULT_PROFILE if set
.PARAMETER VaultProfile
    Which ACME challenge method to use, 'http-01' or 'dns-01'
.PARAMETER ChallengeType
    Which ACMESharp challenge handler to use, e.g. 'awsRoute53'
.PARAMETER ChallengeHandler
    Hash table or parametrs for the challenge handler, e.g. @{HostedZoneId="ZA1234567890";AwsProfileName="myuser"}
.PARAMETER ChallengeParameters
.EXAMPLE
    C:\PS> Update-Certificate -alias "www-mydomain" -domain "www.mydomain.com" -websiteName "My Website"
    This command creates a certificate for www.mydomain.com which is hosted by the web site named 'My Website' using the default http-01 challenge method
.EXAMPLE
    C:\PS> Update-Certificate -alias "www-mydomain" -domain "www.mydomain.com" -websiteName "My Website" -domains @{"alias1"="my.domain.com";"alias2"="other.domain.com"}
    This command will generate a certificate for use with all the domains 'www.mydomain.com', 'my.domain.com' and 'other.domain.com'
.EXAMPLE
    C:\PS> Update-Certificate -alias "www-mydomain" -domain "www.mydomain.com" -websiteName "My Website" -ChallengeType "dns-01" -ChallengeHandler "awsRoute53" -ChallengeParameters @{HostedZoneId="ZA1234567890";AwsProfileName="myuser"}
    This command creates a certificate for www.mydomain.com which is hosted by the web site named 'My Website' using the specified dns-01 challenge method, handler, and parameters
.NOTES
    Author: Bill Seddon
    History:
       January 25th, 2016   Initial version
       February 6th 2016    Updated to support alternative names, update the IIS SSL binding and allow some Csr parameters to be defined
       January 2017         Updated by Aaron Roydhouse to support dns-01 challenges using AWS Route 53, and other challenge methods 
#>
Function Update-Certificate
{
    param
    (
        [Parameter(Mandatory=$true, Position=0, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="An alias to identify this attempt to create a certificate")
        ]
        [ValidateNotNullOrEmpty()]
        [string]$alias, # "wordpressroute",
        [Parameter(Mandatory=$true,  
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="The domain for which you want to create/renew a certificate")
        ]
        [ValidateNotNullOrEmpty()]
        [string]$domain, # = "wordpress.wproute.com",
        [Parameter( 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage='A hashtable of additional domains for which you want to create/renew a certificate: @{"alias1"="my.domain.com";"alias2"="other.domain.com"}')
        ]
        [ValidateNotNullOrEmpty()]
        [HashTable]$domains = @{}, # = ("alias1","my.domain.com"),("alias2","other.domain.com")
        [Parameter(Mandatory=$false, 
            ValueFromPipeline=$true,
            ValueFromPipelineByPropertyName=$true,
            HelpMessage="The name of the IIS web site associated with the certificate being generated such as 'Default Web Site'")]
        [ValidateNotNullOrEmpty()]
        [string]$WebSiteName,
        [Parameter(HelpMessage="The module to overwrite an existing certificate in the temporary certificate location if there is one by default. You can prevent overwriting by enabling this switch.")]
        [switch]$noCertOverwrite = $false,
        [Parameter(HelpMessage="The temporary location to which the created certification should be save")]
        [string]$certFolder = $env:temp, # "C:\Users\Administrator\Downloads",
        [Parameter(HelpMessage="The OS certificate store folder to which you want to import the generated certificate")]
        [string]$certPath = "\LocalMachine\WebHosting",
        [Parameter(HelpMessage="The location of the ACMESharp folder")]
        [string]$location,
        [Parameter(HelpMessage="The country (C) to display in the certificate")]
        [string]$Country,
        [Parameter(HelpMessage="The state or province (ST) to display in the certificate")]
        [string]$StateOrProvince,
        [Parameter(HelpMessage="The organization (O) to display in the certificate")]
        [string]$Organization,
        [Parameter(HelpMessage="The the organization unit (OU) to display in the certificate")]
        [string]$OrganizationUnit,
        [Parameter(HelpMessage="The Description to display in the certificate")]
        [string]$Description,
        [Parameter(HelpMessage="The email address to display in the certificate")]
        [string]$Email,
        [Parameter(HelpMessage="Provided if the parameters are to be check but the process not executed")]
        [switch]$checkParameters = $false,
        [Parameter(HelpMessage="Use this option if IIS is not to be updated")]
        [switch]$notIIS = $false,
        [Parameter(HelpMessage="Set this option to true if old certificates for the domain are to be retained (by default they are removed)")]
        [switch]$keepOldCertificates = $false,
        [Parameter(HelpMessage="ACMESharp vault profile, will default to "":user"", or "":system"" if elevated, or \`$env:ACMESHARP_VAULT_PROFILE if set")]
        [string]$VaultProfile = "",
        [Parameter(HelpMessage="Which ACME challenge method to use, ""http-01"" or ""dns-01""")]
        [string]$ChallengeType = "http-01",
        [Parameter(HelpMessage="Which ACMESharp challenge handler to use, e.g. ""awsRoute53"" or ""manual""")]
        [string]$ChallengeHandler = "manual",
        [Parameter(HelpMessage="Hash table or parametrs for the challenge handler, e.g. @{HostedZoneId=""ZX1234567890"";AwsProfileName=""myuser""}")]
        [HashTable]$ChallengeParameters = @{}
    )

    # Check an alias has been provided
    if ( ! $alias )
    {
        "You must supply a value for the alias to use for this attempt to create a certificate"
    }

    # Check an domain has been provided
    if ( ! $domain )
    {
        "You must supply a value for the domain for which you want to create a certificate"
    }

    if ( ! $notIIS )
    {
        # Check an web site has been provided, if we are to install in IIS
        if ( ! $WebSiteName )
        {
            "The name of a web server must be provided"
        }

        # The $websiteFolder must exist
        $webSite = Get-Website -Name $WebSiteName

        if ( ! $webSite )
        {
            "The Web Site '$WebSiteName' does not exist"
        }
    }

    # The three mandatory parameters must exist

    if ( ! $alias -or ! $domain -or (! $notIIS -and (! $WebSiteName -or ! $webSite ) ) )
    {
        "Must supply domain, alias, and for IIS installs a website"
        return
    }

    # Check the domains

    # Each element of the array must be an array of length two
    if ( ($domains | Where-Object { $_ -is [System.Collections.Hashtable] }).Count -ne $domains.Count )
    {
        "Each element of the 'domains' array must be an alias/domain (key/value) pair"
        return
    }

    # The $domains list cannot include the $domain as an alternative
    if ( $domains.GetEnumerator() | Where-Object { $_.Value -eq $domain } )
    {
        "The main domain '$domain' cannot also be included as an alternative"
        return
    }

    # The $domains list cannot include the $domain as an alternative
    if ( $domains.GetEnumerator() | Where-Object { $_.Key -eq $alias } )
    {
        "The main alias '$alias' cannot also be included as an alternative"
        return
    }

    # Add the main alias to the domains list so they can all be processed together
    $domains[$alias] = $domain

    # To use http-01 with IIS the website needs to be operating
    if ( (! ($webSite.State -eq "Started")) -and (! ($ChallengeType -eq "http-01")) -and (! $notIIS) )
    {
        "The web site '$WebSiteName' is not started. It will not be possible to complete the http-01 challenge"
        return
    }

    # If the certificate is to be install in IIS then check the bindings already exist
    if ( ! $notIIS)
    {
        # Check that the domains for which certificates are to be generated have an https binding in the web site
        $invalidDomains = $domains.GetEnumerator() | 
            Where-Object { $dom = $_.Value;
                ! (Get-WebBinding -HostHeader $_.Value -Protocol https) -or 
                ! ( $webSite.bindings.Collection | Where-Object { $_.protocol -eq 'https' -and $_.bindingInformation -like "*:$dom*" } ) 
            }
    
        if ( $invalidDomains.Count -gt 0 )
        {
            "The following domain(s) do not have an https binding in the web site '$WebSiteName': {0}" -f  (@( $invalidDomains | ForEach-Object { $_.Value } ) -join ",")
            "Please add binding(s) in IIS before using these domain(s)"
            return;
        }
    }

    $csrDetails = @{}
    if ( $Country ) { $csrDetails["Country"]=$Country }
    if ( $StateOrProvince ) { $csrDetails["StateOrProvince"]=$StateOrProvince }
    if ( $Organization ) { $csrDetails["Organization"]=$Organization }
    if ( $OrganizationUnit ) { $csrDetails["OrganizationUnit"]=$OrganizationUnit }
    if ( $Description ) { $csrDetails["Description"]=$Description }
    if ( $Email ) { $csrDetails["Email"]=$Email }

    "aliases/domains:"
    $domains.GetEnumerator() | ForEach-Object { "    $($_.Key)=$($_.Value)" } 

    if (! $notIIS)
    {
        $websiteFolder = $webSite.physicalPath
        $websiteFolder = [System.Environment]::ExpandEnvironmentVariables($websiteFolder)

        "Web Site Name: $WebSiteName"
        "Web Site Folder: $websiteFolder"
    }
    "Cert Folder: $certFolder"

    if ( $csrDetails.Count -gt 0 )
    {
        "csr Details:"
        $csrDetails.GetEnumerator() | ForEach-Object { "    $($_.Key)=$($_.Value)" } 
    }

    if ( $checkParameters ) { return }


    $certalias = "cert$alias"
    $mainalias = $alias # The value '$alias' will change but this value is needed to generate the certificate
    $maindomain = $domain # The value '$domain' will change but this value is needed to generate the certificate
    $pfx = "cert$alias.pfx"
    $filepath = "$certFolder\$pfx"

    $location = if ( $location ) { $location } else { $PSScriptRoot }
    Set-Location -Path $location

	$ACMESharpModule = "ACMESharp"

	if ( ! (get-module $ACMESharpModule) ) 
	{
		"Importing $ACMESharpModule"
		Import-Module $ACMESharpModule -ErrorAction SilentlyContinue
		if ( ! (get-module $ACMESharpModule) ) 
		{
			"!!!"
			"!!! The module '$ACMESharpModule' was not loaded because no valid "
			"!!! module file was found in any PowerShell module directory."
			"!!!"
			"!!! Please install $ACMESharpModule.  For more information please visit:"
			"!!! https://github.com/ebekker/ACMESharp/wiki/Quick-Start"
			"!!!"
			return
		}
	}

    # A message will be displayed if the vault exists
    if ( ! (Get-ACMEVault -VaultProfile $VaultProfile) )
    {
        "ACMESharp vault $VaultProfile does not exist"
        "Create it with e.g. for default ':user' profile:"
        "Initialize-ACMEVault"
        "or for a named profile like 'Test':"
        "Set-ACMEVaultprofile -ProfileName Test -Provider local -VaultParameters @{RootPath='C:\Users\MyUser\AppData\Local\ACMESharp\testVault';CreatePath=[bool]'True'}"
        "Initialize-ACMEVault -BaseService LetsEncrypt-STAGING -VaultProfile Test"
    }

    if ( ! ((Get-ACMEVault -VaultProfile $VaultProfile).Registrations.Count) )
    {
        "There are no registrations. This process cannot proceed until a registration has been created"
        "Issue a PowerShell command like: New-ACMERegistration -Contacts mailto:somebody@example.org -AcceptTos"
        return
    }

    if ( ! (Get-ACMEChallengeHandlerProfile -GetChallengeType $ChallengeType) )
    {
        "Not a supported ACME challenge type: $ChallengeType"
        "Supported types are:"
        Get-ACMEChallengeHandlerProfile -ListChallengeTypes
    }

    if ( ! (Get-ACMEChallengeHandlerProfile -GetChallengeHandler $ChallengeHandler) )
    {
        "Not a supported ACME challenge handler: $ChallengeHandler"
        "Supported handlers are:"
        Get-ACMEChallengeHandlerProfile -ListChallengeHandlers
    }

    #

    <#
     * Begin looping over the requested domains to create or find the respective identifiers
     * TODO: It would be faster to prepare all challenges first, and then request ACME to validate them all, especially for dns-01 challenges
     #>

    $identifiers = @{}
    $challenges = @{}

    $domains.GetEnumerator() | ForEach-Object {

        $alias = $_.Key
        $domain = $_.Value

        if ( ! ( (Get-ACMEVault -VaultProfile $VaultProfile).Identifiers.Count -and (Get-ACMEIdentifier -VaultProfile $VaultProfile | Where-Object { $_.Alias -eq "$alias" }).Count ) )
        {
            "Create identifier for '$domain' using alias '$alias'"
            $result = New-ACMEIdentifier -VaultProfile $VaultProfile -Dns $domain -Alias $alias
        }
        else
        {
            "The identifier '$alias' already exists"
            $result = Get-ACMEIdentifier -VaultProfile $VaultProfile $alias
        }

        $identifiers[$alias] = $result

        <#  Before Complete
            ChallengePart          : ACMESharp.Messages.ChallengePart
            Challenge              : 
            Type                   : http-01
            Uri                    : https://acme-v01.api.letsencrypt.org/acme/challenge/arCMu_9OqjPSnknZR9T39Q1fh3vyhMVOi5z8ZYGwoHE/10635610
            Token                  : J1TtfKn0iikqKwMXxJQgI7qGKgsJ7Tq68VXUaR-pyoI
            Status                 : pending
            OldChallengeAnswer     : [, ]
            ChallengeAnswerMessage : 
            HandlerName            : 
            HandlerHandleDate      : 
            HandlerCleanUpDate     : 
            SubmitDate             : 
            SubmitResponse         : 
         #>        

        # Is this identifier already valid?
        if ( ! ($result.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.SubmitDate }).Count )
        {
            # No?  Has the request been submitted?
            if ( ! ($result.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.HandlerName -eq $ChallengeHandler }).Count )
            {
                "Issue challenge for '$alias'"
                $result = Complete-ACMEChallenge $alias -VaultProfile $VaultProfile -ChallengeType $ChallengeType -Handler $ChallengeHandler -HandlerParameters $ChallengeParameters
            }

            <#  After complete
                ChallengePart          : ACMESharp.Messages.ChallengePart
                Challenge              : ACMESharp.ACME.HttpChallenge
                Type                   : http-01
                Uri                    : https://acme-v01.api.letsencrypt.org/acme/challenge/arCMu_9OqjPSnknZR9T39Q1fh3vyhMVOi5z8ZYGwoHE/10635610
                Token                  : J1TtfKn0iikqKwMXxJQgI7qGKgsJ7Tq68VXUaR-pyoI
                Status                 : pending
                OldChallengeAnswer     : [, ]
                ChallengeAnswerMessage : 
                HandlerName            : manual
                HandlerHandleDate      : 1/25/2016 1:44:55 AM
                HandlerCleanUpDate     : 
                SubmitDate             : 
                SubmitResponse         : 
            #>

            # If this is a dns-01 challenge using AWS Route 53, then wait for the DNS entries to sync
            # ACMESharp should to the Route53 GetChange API method to wait for the sync itself, but doesn't yet
            if ( ($ChallengeType -eq "dns-01") -and ($ChallengeHandler -eq "awsRoute53") )
            {
                # Waiting for AWS Route 53 record to sync to all name servers
                "Waiting for new Route 53 DNS record to sync"
                Start-Sleep -Milliseconds 30000
            }

            # If this is a manual http-01 challenge using IIS, then up to us to add the file into the webroot
            # In all other cases the ACMESharp challenge handler should do the work
            if ( ($ChallengeType -eq "http-01") -and ($ChallengeHandler -eq "manual") -and ! $notIIS )
            {
              $content = ""
              $path = ""
              $result.Challenges | Where-Object { $_.Type -eq $ChallengeType } | ForEach-Object { $content = $_.Challenge.FileContent; $path = $_.Challenge.FilePath }
              if ( ! $content )
              {
                  "There is no content available after beginning the challenge"
                  return
              }

              "Content: $content"
              "Path: $path"
  
              "Saving the challenge content"
              New-Item -Path "$websiteFolder\$path" -ItemType File -Force
              # Can't use Out-File cmdlet because it output a trailing new line
              [io.file]::WriteAllText("$websiteFolder\$path",$content)
            }
  
            # Assume that DNS record or the .well-known/acme-challenge/xxx file is in place
            "Submit challenge for '$alias'"
            $result = Submit-ACMEChallenge $alias -VaultProfile $VaultProfile -ChallengeType $ChallengeType

            $challenges[$alias] = $result

            <#  After submit
                ChallengePart          : ACMESharp.Messages.ChallengePart
                Challenge              : ACMESharp.ACME.HttpChallenge
                Type                   : http-01
                Uri                    : https://acme-v01.api.letsencrypt.org/acme/challenge/AbLhGZFSDlAZ-V_tz_JsHpLUecZStsT-0pXqx91tTR0/10636625
                Token                  : 8NvzB46821JxizVdwdUCiKwtetAJGKazKd7J1zKC5ww
                Status                 : pending
                OldChallengeAnswer     : [, ]
                ChallengeAnswerMessage : 
                HandlerName            : manual
                HandlerHandleDate      : 1/25/2016 1:49:14 AM
                HandlerCleanUpDate     : 
                SubmitDate             : 1/25/2016 1:49:47 AM
                SubmitResponse         : ACMESharp.AcmeClient+AcmeHttpResponse
            #>
        }
        else
        {
            "The identifier '$alias' has been already been submitted"
        }

    }

    # Check for validity here.  If not valid update the identifier
    $domains.GetEnumerator() | ForEach-Object {

        $alias = $_.Key
        $domain = $_.Value

        if ( $identifiers[$alias].Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -eq 'valid' } ) { "$alias is valid"; return }
        if ( $identifiers[$alias].Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -eq 'invalid' } ) { "$alias is invalid"; return }

        $result = Update-ACMEIdentifier $alias -VaultProfile $VaultProfile -ChallengeType $ChallengeType
        $identifiers[$alias] = $result

    }

    # If there are any invalid challenges then its time to abort
    $abort = $false;
    $identifiers.GetEnumerator() | ForEach-Object {

        $alias = $_.Key

        if ( ($_.Value.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -eq 'invalid' } ) )
        {
            $abort = $true;
            "One or more of the challenges of the identifier for alias '$alias' is invalid"
        }
    }

    if ( $abort ) { return }


    # Now check the the challenges

    $maxAttempts = 10
    $attempts = 0
    while ( ($identifiers | Where-Object { $_.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -ne 'valid' } } ) )
    {
        $attempts++
        if ( $attempts -gt $maxAttempts )
        {
            "The request to validate a challenge request has not succeeded in $maxAttempts attempts"
            return
        }

        # Update the identifier
        "Updating the identifier in 10 seconds..."
        Start-Sleep -Milliseconds 10000

        $domains.GetEnumerator() | ForEach-Object {

            $alias = $_.Key

            $result = $identifiers[$alias]

            if ( ( $result.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -eq 'pending' } ) )
            {
                $result = Update-ACMEIdentifier $alias -VaultProfile $VaultProfile -ChallengeType $ChallengeType
                $identifiers[$alias] = $result
                if ( ($result.Challenges | Where-Object { $_.Type -eq $ChallengeType -and $_.Status -eq 'invalid' } ) )
                {
                    "The identifier for alias '$alias' is not valid"
                    return
                }
            }

        }
    }
    
    # Now the challenge validation is complete, we can clean up the temporary challenge files or DNS records that were created
    $challenges.GetEnumerator() | ForEach-Object {

        $alias = $_.Key
        $domain = $_.Value

        "Cleaning challenge for '$alias'"
        $result = Complete-ACMEChallenge $alias -VaultProfile $VaultProfile -ChallengeType $ChallengeType -Handler $ChallengeHandler -HandlerParameters $ChallengeParameters -Clean

        if ( ($ChallengeType -eq "http-01") -and ($ChanllengeHandler -eq "manual") -and ! $notIIS )
        {
            # TODO: Clean up (remove) all the challenge folders created by this script
            # Remove-Item -Path "$websiteFolder\$path"
        }
    }

    # "Complete"
    # return

    <#
        This is what an unsubmitted certificate look like

        Id                       : 4a3b194d-6a4c-4ced-8d0b-d1626431b72c
        Alias                    : certwordpressstrongtyping-2016-02-06
        Label                    : 
        Memo                     : 
        IdentifierRef            : 25c43cde-999b-4642-93be-d5bf12059458
        IdentifierDns            : wordpress.strongtyping.com
        AlternativeIdentifierDns : 
        KeyPemFile               : 
        CsrPemFile               : 
        GenerateDetailsFile      : 4a3b194d-6a4c-4ced-8d0b-d1626431b72c-gen.json
        CertificateRequest       : 
        CrtPemFile               : 
        CrtDerFile               : 
        IssuerSerialNumber       : 
        SerialNumber             : 
        Thumbprint               : 
        Signature                : 
        SignatureAlgorithm       : 
     #>

    try
    {
        $result = Get-ACMECertificate $certalias -VaultProfile $VaultProfile
        "A certificate for '$mainalias' already exists with id $($result.Id)"

        <# The New-ACMECertificate may have been executed but not submitted.  Here's what the output looks like after issuing the 'New' command

            Id                       : 585d3bd3-358f-4dac-9046-4d709c6d40a3
            Alias                    : certwproutecom-2016-02-21-2
            Label                    : 
            Memo                     : 
            IdentifierRef            : fcb838e4-8208-4901-a8d2-e25eea965362
            IdentifierDns            : www.wproute.com
            AlternativeIdentifierDns : {www.wproute.co.uk, www.wp-route.com, www.wp-route.co.uk}
            KeyPemFile               : 
            CsrPemFile               : 
            GenerateDetailsFile      : 585d3bd3-358f-4dac-9046-4d709c6d40a3-gen.json
            CertificateRequest       : 
            CrtPemFile               : 
            CrtDerFile               : 
            IssuerSerialNumber       : 
            SerialNumber             : 
            Thumbprint               : 
            Signature                : 
            SignatureAlgorithm       :

           And here's what it might look like after:

            Id                       : 585d3bd3-358f-4dac-9046-4d709c6d40a3
            Alias                    : certwproutecom-2016-02-21-2
            Label                    : 
            Memo                     : 
            IdentifierRef            : fcb838e4-8208-4901-a8d2-e25eea965362
            IdentifierDns            : www.wproute.com
            AlternativeIdentifierDns : {www.wproute.co.uk, www.wp-route.com, www.wp-route.co.uk}
            KeyPemFile               : 585d3bd3-358f-4dac-9046-4d709c6d40a3-key.pem
            CsrPemFile               : 585d3bd3-358f-4dac-9046-4d709c6d40a3-csr.pem
            GenerateDetailsFile      : 585d3bd3-358f-4dac-9046-4d709c6d40a3-gen.json
            CertificateRequest       : ACMESharp.CertificateRequest
            CrtPemFile               : 585d3bd3-358f-4dac-9046-4d709c6d40a3-crt.pem
            CrtDerFile               : 585d3bd3-358f-4dac-9046-4d709c6d40a3-crt.der
            IssuerSerialNumber       : 
            SerialNumber             : 016795AE9CA42058B6EA700FB1A159AE48D9
            Thumbprint               : 338ED04BBFFC3136FD0AAAA0DB7389E63B9FF3C1
            Signature                : 338ED04BBFFC3136FD0AAAA0DB7389E63B9FF3C1
            SignatureAlgorithm       : sha256RSA


        #>
    }
    catch
    {
        # OK, time to create the certificate and submit it
        "Creating a new certificate for domain '$maindomain' with alias '$certalias'"
        if ( $domains.Count -gt 1 )
        {
            "  With these alternative names:"
            "  {0}" -f  ( ( [array]($domains.GetEnumerator() | Where-Object { $_.Key -ne $mainalias } | ForEach-Object { $_.Value } ) -join "," ) )   
        }

        $new = New-ACMECertificate $mainalias -VaultProfile $VaultProfile -Generate -Alias $certalias -CsrDetails $csrDetails -AlternativeIdentifierRefs ([array]($domains.GetEnumerator() | Where-Object { $_.Key -ne $mainalias } | ForEach-Object { $_.Key } ))

        try
        {
            $error.Clear()
            $result = Submit-ACMECertificate $certalias -VaultProfile $VaultProfile
        }
        catch
        {
            "!!! Certificate submission failed"
            $error
            return
        }
    }

    # Check to see if a issuer serial number is available - if so, we are OK
    $result = Update-ACMECertificate $certalias -VaultProfile $VaultProfile
    $attempts = 0
    while ( $result.IssuerSerialNumber -eq $null ) 
    {
        $attempts++
        if ( $attempts -gt $maxAttempts )
        {
            "The request to validate a challenge request has not succeeded in $maxAttempts attempts"
            return
        }

        "Updating the certificate in 10 seconds..."
        Start-Sleep -Milliseconds 10000
        $result = Update-ACMECertificate $certalias -VaultProfile $VaultProfile
    }

    $thumbprint = $result.ThumbPrint

    "The current ACME certificate has id '$($result.Id)' and thumbprint '$thumbprint'"

    # Export the certificate so it can be imported into IIS
    if ( ! $noCertOverwrite -or ! (Get-ChildItem -Path $filepath) )
    { 
        $result = Get-ACMECertificate $certalias -VaultProfile $VaultProfile -ExportPkcs12 $filepath -Overwrite
    }
    else
    {
        $result = Get-PfxCertificate -FilePath $filepath
        "noCertOverwrite parameter specified but there is an existing certificate."
        if ( $result.ThumbPrint -ne $thumbprint )
        {
            "Warning: The thumbprint of the ACME certificate ($($result.ThumbPrint))"
            "does not match the thumbprint of the existing certificate ($thumbprint)"
            $thumbprint = $result.ThumbPrint
        }
    }

    "Certificate exported with thumbprint '$thumbprint'"

    if ( -not $keepOldCertificates )
    {
        "Removing existing certificates with '$maindomain' as the common name"
        get-childitem "cert:$certPath" | Where-Object { $_.Subject -eq "CN=$maindomain" }  | Remove-Item
    }

    # Now import the certificate
    "Importing to $certPath from $filepath"
    $import_result = Import-PfxCertificate -CertStoreLocation "cert:$certPath" -FilePath $filepath -Exportable

    $expires = ((Get-Item "Cert:$certpath\$thumbprint").notAfter).ToString("yyyy-MM-dd")
    $friendly = "$maindomain $expires ACME"
    "Setting friendly name to '$friendly'"
    (Get-Item "Cert:$certpath\$thumbprint").FriendlyName = "$friendly"

    if ( ! $notIIS )
    {
        # Update the certificate bindings
        $domains.GetEnumerator() | ForEach-Object {
    
            $alias = $_.Key
            $domain = $_.Value
    
            # Remove the existing binding.  The binding must be here, a check was made at the beginning
            "Removing the SSL certificate for '$domain'"
            remove-item -path "IIS:\SslBindings\*!443!$domain"
            "Adding the SSL certificate with thumb print '$thumbprint' for '$domain'"
            $result = New-Item -Path "IIS:\SslBindings\*!443!$domain" -Value $import_result -SSLFlags 1
        }    
    }

    "Done"
}
