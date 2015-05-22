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
				1. generate a key pair
				2. create a CSR
				3. import certificates
				4. configure servers
				
   -configure <alias>	- configuring the RSA AM to use a certificate with <alias>
   
   -list [<alias>]	- list a certificate with <alias> or all certificate in the identity and root keystores
   
   -delete <alias>	- delete the <alias> from all keystores (identity, root, JKD trusted)
```   

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
