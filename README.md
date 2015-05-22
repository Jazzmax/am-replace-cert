# am-replace-cert

Author : Maxim Siyazov 

Certificate replacement tool for RSA Authentication Manager Appliance 3.0.4 or RSA Authentication Manager 7.1 SP4 on Red Hat Linux.

The script will help to go through the system certificate replacement procedure. 

## Installation

Copy the script in to directory that emcsrv and rsaadmin users have access to, e.g. /tmp.

Make sure to have the following pre-requisite met (or the script will gracefully stop)
- This script should be run as "rsaadmin".

## Usage
```
./am-replace-cert.sh [OPTION] alias

    <alias> 		- whole certificate replacement procedure:
				1. generate a key pair and create a CSR
				2. import certificates
				3. configure servers
				
   -configure <alias>	- configuring the RSA AM to use a certificate with <alias>
   
   -list [<alias>]	- list a certificate with <alias> or all certificate in the identity and root keystores
   
   -delete <alias>	- delete the <alias> from all keystores (identity, root, JKD trusted)
```   

This script must be run as "rsaadmin" user. Run "sudo su rsaadmin" to become rsaadmin.

By default the script will be looking for new certificate files in the /tmp directory. This can be changed by editing the variable CERTSPATH in the global variables section of the script.
The script will prompt for the AM master password to retrieve keystore's passwords.

Copy the script over to the AM box under /tmp directory using (WinSCP) and make it executable by running:

chmod +x am-replace-cert.sh

When run with the only certificate alias name as an argument it will go through all three steps to replace the installed server certificate. Depending on the current state of the key store it will continue the procedure from the point where stopped last time. For example:

./am-replace-cert.sh newacertaias

#### STAGE 1. Generating New Keys and a Certificate Signing Request (CSR).

a. Retrieving Keystore Passwords
b. Generating New Keys
  * you will be prompted to enter password to protect a newly generated private key (must be at least 6 characters).
  * 2048 bit keys are generated and no option to change it.

c. Creating CSR

A newly created CSR in PEM format will be displayed to you and additionally a SCR file will be written to the /tmp.

Submit the request to your certificate authority (CA). For more information, talk to your CA administrator.

#### STAGE 2. Importing the Certificates

a. Prior importing any certificate the script will check the pre-requisites:
  1. Signature algorithm - only sha1 is supported.
  2. If you use a certificate that contains any extended key usage (EKU) fields marked critical, both of the following key usage extensions must be present:
   * serverAuth (1.3.6.1.5.5.7.3.1) -- TLS Web server authentication;
   * clientAuth (1.3.6.1.5.5.7.3.2) -- TLS Web client authentication.

  3. CN of the server certificate must be FQDN of the server. No SAN or wildcards supported. 

b. Verify the full certification path

c. Import the CA root certificate (the intermediate CA certificates if any) into the root keystore

e. Import the CA root certificate (and the intermediate CA certificates if any) into the server keystore

f. Import the signed server certificate into the server keystore

g. Import the CA root certificate into the JDK CA certificate keystore

#### STAGE 3. Configuring the RSA Authentication Manager Servers and Restarting Authentication Manager

a. Prior configuring the AM servers to use the new certificate the script will: 

  * take a backup of current Weblogic configuration;
  * ensure the the required AM servers are running.

b. Configure the RSA Authentication Manager Administration Server

c. Configure the RSA Authentication Manager Proxy Server

d. Configure the RSA Authentication Manager

e. Restart the RSA Authentication Manager

f. Check if the RSA Authentication Manager Servers are successfully started. 
   If failed the script will restore the saved Weblogic configuration and restart AM.

## Contributing

1. Fork it!
2. Create your feature branch: `git checkout -b my-new-feature`
3. Commit your changes: `git commit -am 'Add some feature'`
4. Push to the branch: `git push origin my-new-feature`
5. Submit a pull request :D

## History

TODO: Write history

## Credits


## License

TODO: Write license
