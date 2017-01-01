# Issue/renew and install SSL certificates in IIS using an ACME service like Let's Encrypt

The starting point for this repository is [@bseddon](https://github.com/bseddon)'s `Update-Certificate-http.ps` script. The script for using [@ebrekker](https://github.com/ebekker)'s [ACMESharp](https://github.com/ebekker/ACMESharp) libraries to issue and insatll certificates on IIS. It uses the `http-01` ACME challenge method.

The goal of this fork is it extend the script to handle the `dns-01` ACME challenge method using the AWS Route 53 API.

The repository has no explicit license, because I don't know the licence status of @bseddon's code.
