# Issue and optionally install SSL certificates in IIS using an ACME service like Let's Encrypt

The starting point for this repository is [@bseddon](https://github.com/bseddon)'s `Update-Certificate-http.ps` script. The script for using [@ebekker](https://github.com/ebekker)'s [ACMESharp](https://github.com/ebekker/ACMESharp) libraries to issue and install certificates on IIS. It uses the `http-01` ACME challenge method. @bseddon has since release his code under an MIT license in [his own repository](https://github.com/whereisaaron/acmesharp-script).

The goal of this fork is it extend the script to handle the `dns-01` ACME challenge method using the [AWS Route 53](https://aws.amazon.com/route53/) API.

## Additional Features

* Supports multiple ACMESharp vaults via the `-VaultProfile` parameter
* Supports different challenge methods via `-ChallengeType`, `-ChallengeHandler`, and `-ChallengeParameters` parameters, including `http-01` and `dns-01`
* Support issuing certificates without IIS
* Minor bug fixes and log output tweaks

## Update-Certificate.ps1

This script is a more general version of @bseddon's `Update-Certificate-http.ps1` that supports any ACME challenge method supported by ACMESharp. It has been tested with `http-01` and `dns-01`. Certificates issued using `http-01` require a running IIS website with an existing HTTP binding for the certificate domain names that in Internet accessible. Certificates issued using dns-01 do not require an accessible website or even IIS at all.

The following example would issue a certificate for IIS website 'www.example.com' and install it in Windows and IIS. The IIS website 'www.example.com' must be running, be Internet accessible, have an HTTP binding for 'www.example.com', and not have any password or URL rewriting or configuration to prevent access to the '.acme-challenge' folder in the website root directory.

```
Update-Certificate -alias "www1" -domain "www.example.com" -websiteName "My Website" -ChallengeType "http-01"
```

The following example would issue a certificate for IIS website 'www.example.com' and install it in Windows and IIS. The website need not be running or Internet accessible. It requires an AWS IAM user with access to add and delete TXT records the public 'example.com' zone in AWS Route 53.

```
Update-Certificate -alias "www1" -domain "www.example.com" -websiteName "My Website" -ChallengeType "dns-01" -ChallengeHandler "awsRoute53" -ChallengeParameters @{HostedZoneId="ZX1234567890";AwsProfileName="default"}
```

The following example would issue a certificate 'api.example.com' and install it in Windows. A running website or IIS is not required. You may need to script additional steps to get your service or application to use the new certificate.

```
Update-Certificate -alias "api1" -domain "api.example.com" -notIIS -ChallengeType "dns-01" -ChallengeHandler "awsRoute53" -ChallengeParameters @{HostedZoneId="$vpcZoneId";AwsProfileName="default"}
```

You can also issue certificates for multiple domains names using the `-domains` hash table argument to specify the additional domains. Each domain must be bound to the existing website for `http-01` or be in the same domain/zone for `dns-01`.

## Renew-All-Certificates.ps1

This is an example script that could be scheduled to run regularly to renew a list of certificates. It adds a date suffix to teh ACMESharp certificate domain name identifiers to ensure a new certificate is issued each day it is run. This is required because ACMESharp does not currently support renewing certificates, only issuing new certificates. This script should be scheduled to run once every one or two months. This script also uses @barnybug's [cli53](https://github.com/barnybug/cli53) tool to automatically identify the Route 53 Zone ID.

## Run-Renew-All-Certificates.cmd

It is often easier to schedule CMD scripts in Windows than PowerShell. This script runs the `Renew-All-Certificates.ps1` script and redirects output to `LastRun.log`. Schedule it to run in the same folder as the `Renew-All-Certificates.ps1` and `Update-Certificate.ps1` scripts.

## To Do

* The ACMEScript AWS Route 53 challenge handler should be able to identify the correct Zone Id for each challenge domain name itself. This can be done my checking for the longest suffix of the domain name for which there is a zone in Royte 53. This would negate the need to specify Zone IDs and would allow certificates for multiple domain names from different zones.
* The built in handling of 'http-01' in the script should clean up the challenge files it creates in the website after the challenge is complete. This mechanism could also be replaced by ACMESharp's 'iis' challenge handler.
