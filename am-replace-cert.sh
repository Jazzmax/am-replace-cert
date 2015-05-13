#!/bin/bash
VER=1.1
##########################################################
#
# This script will assist to replace a server certificate on AM 7.1 appliance
##########################################################

##########################################################
# Usage: ./replace-cert.sh
#  options:  -import : Imports new certificates 
#            -config : To do. Reconfigurates Weblogic to use a new server certificate.
#			 -delete : delete the cert from the all keystores 
#			 -list	 : list keystores
#			 
##########################################################
# Author : Maxim Siyazov
# Version History
# 0.80  - Initial version
# 0.91  - added +list keystores, +delete alias from all keystores, +import certs, many other improvements 
# 0.92  - some bug fixes
# 0.93  - changed mechanism of loading a chain of certificates.
# 1.0   - the initial release. *improved configuring the AM servers, added a backup/restore the WebLogic config
# 1.1   - added check of the Signature Algorithm (AM-26699), +bug fixes.
# -------------------------------
# TO DO
# - Expiration check
# - 

###########################################################
# Prompt a question and read answer
# Param 1: Question
# Param 2: default answer
###########################################################
promptYesNo(){

  echo -n "$1 (y/n) [$2] "
  read answer
  answer=`echo $answer | tr [A-Z] [a-z]`
  if [ -z "$answer" ]; then
    answer=$2
  fi
  if [ "xy" = "x$answer" ]; then
    return 1
  else
    return 0
  fi
}

###########################################################
# Prints the usage and exits
#
usage() {

    echo -e "Usage: replace_cert.sh {-gencsr|-import|-config|-list|-delete}"
    echo -e "This script should be run as rsaadmin\n"
	echo -e  "   -gencsr <alias>"
	echo -e  "Generating a new key pair and a Certificate Signing Request\n"
	echo -e  "   -import <alias>"
	echo -e  "Importing the full chain of certificates into keystores\n"
	echo -e  "   -config <alias>"
	echo -e  "Configuring the RSA AM to use a new certificate\n"
	echo -e  "   -list [<alias>]"
	echo -e  "List a certificate with <alias> or all certificate in the keystores\n"
	echo -e  "   -delete <alias>"
	echo -e  "Delete the <alias> from all keystores\n"

    exit 1
} # End of usage



############################################################
# Generating New Keys and a Certificate Signing Request
# 
gencsr(){

$RSAAM_HOME/utils/rsautil manage-ssl-certificate --genkey --alias "$ALIAS" --dname "CN=$FQDN" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW

$RSAAM_HOME/utils/rsautil manage-ssl-certificate --certreq --alias "$ALIAS" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks --csr-file "/tmp/${ALIAS}_csr.pem" -m $MASTER_PW --storepass $ID_STORE_PW

if [ ! -f "/tmp/${ALIAS}_csr.pem" ]; then
  echo "CSR not generated in /tmp/. Exiting"
  exit 1
fi

chmod 777 "/tmp/${ALIAS}_csr.pem"

echo "Please submit the request file /tmp/${ALIAS}_csr.pem  to your certificate authority."
echo "/tmp/${ALIAS}_csr.pem"
cat "/tmp/${ALIAS}_csr.pem"

echo "Before completing the procedure, save the CA root certificate (and any intermediate CA certificates), and \ the signed server certificate you received from the certificate authority in a location of \
your choosing on the Authentication Manager server, /tmp/certs/ by default. \
You will be prompted for this location during the procedures. "
}

############################################################
# Importing the full chain of certificates
#
############################################################
import_certs(){

echo "Importing trusted CA certificates..." 
#importing the CA certs

i=1

while [ "$i" -lt "${#CERTS[@]}" ]
do    
	# Importing CA cert into the root keystore 
	echo "Importing ${CERTS[$i]} into the root keystore "
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --import --trustcacerts --alias "${CERTS[$i]}" --cert-file "${CERTSPATH}${CERTS[$i]}" --keystore $RSAAM_HOME/server/security/root.jks -m $MASTER_PW --storepass $ROOT_STORE_PW
	echo 
	
	# Importing CA cert into the identity keystore 
	echo "Importing ${CERTS[$i]} into the identity keystore "
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --import --trustcacerts --alias "${CERTS[$i]}" --cert-file "${CERTSPATH}${CERTS[$i]}" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW	
	echo 
		
	# Importing CA cert into the JDK CA certificate keystore
	echo "Importing ${CERTS[$i]} into the JDK CA certificate keystore "
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --import --trustcacerts --alias "${CERTS[$i]}" --cert-file "${CERTSPATH}${CERTS[$i]}" --keystore $RSAAM_HOME/appserver/jdk/jre/lib/security/cacerts -m $MASTER_PW --storepass "changeit"
	echo
	
	((i++))
done

echo "Importing the signed server certificate ${CERTS[0]} into the server keystore"
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --import --alias "${ALIAS}" --cert-file "${CERTSPATH}${CERTS[0]}" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW	


}
############################################################
# Configuring the RSA Authentication Manager Servers
# Param 1: certificate alias
configureServers(){
local NEWALIAS=$1

echo "Preparing for configuring the RSA Authentication Manager Servers with the new server certificate"
echo 
# Verify the cert in the store
echo "Verifying a certificate with alias $NEWALIAS. The full chain of certificates should be shown"
echo 
list_certs "$NEWALIAS"
if [ $? -ne 0 ]; then 
	echo 
	echo "The alias \"$NEWALIAS\" not found in the identity store. Exiting."
	exit 1
fi	

promptYesNo "Are you sure you what to configure the RSA AM with the certificate above?" y
		if [ $? -eq 0 ]; then
			echo "Exiting."
			exit 1
		fi 	

echo
echo "Checking to see if the RSA Authentication Manager Servers are running"
	
exec 5>&1
AMSTATUS=`$RSAAM_HOME/server/rsaam status allnoradius | tee >(cat - >&5)`
echo $AMSTATUS	

if [ `echo "$AMSTATUS" | grep "RUNNING" | wc -l` -lt 6 ]; then # 6 services must be running
	echo 
	echo "The RSA Authentication Manager Servers are NOT running. "
	echo "To configure the RSA AM with a new server certificate all RSA AM services mast be running. Use \"$RSAAM_HOME/rsaam start all\" to start the RSA AM."
	echo "Exiting."
	exit 1
fi

echo "OK. All RSA AM services are running."

# Backup the current WebLogiic config file.
echo -e "Taking a backup of the WebLogic configuration..."

NOW=$(date +"%m%d%Y_%H%I")
BACKUP_FILENAME="$RSAAM_HOME/server/config/config_$NOW.xml"

cp $RSAAM_HOME/server/config/config.xml $BACKUP_FILENAME

echo -e "Done. A copy of the Weblogic config.xml saved to $BACKUP_FILENAME"

# Configuring the RSA Authentication Manager Administration Server
echo "Configuring the RSA Authentication Manager Administration Server..."
$RSAAM_HOME/utils/rsautil manage-ssl-certificate --config-server --alias "$NEWALIAS" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW --server-name AdminServer
if [ $? -ne 0 ]; then 
	echo "Failed to configure the Administration Server. Check out the $RSAAM_HOME/server/servers/AdminServer/logs/AdminServer.out for details. Exiting."
	exit 1
fi
 
echo
echo "Done"
pause
	
# Configuring the RSA Authentication Manager Proxy Server:
echo "Configuring the RSA Authentication Manager Proxy Server..."
$RSAAM_HOME/utils/rsautil manage-ssl-certificate --config-server --alias "$NEWALIAS" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW --server-name proxy_server
if [ $? -ne 0 ]; then 
	echo "Failed to configure the  RSA Authentication Manager Proxy Server. Check out the $RSAAM_HOME/server/servers/proxy_server/logs/proxy_server.out for details. Exiting."
	exit 1
fi
echo 
echo "Done"
pause

# Configuring the RSA Authentication Manager:
echo "Configuring the RSA Authentication Manager..."
$RSAAM_HOME/utils/rsautil manage-ssl-certificate --config-server --alias "$NEWALIAS" --keystore $RSAAM_HOME/server/security/${MACHINE_NAME}.jks -m $MASTER_PW --storepass $ID_STORE_PW --server-name ${MACHINE_NAME}_server
if [ $? -ne 0 ]; then 
	echo "Failed to configure the Authentication Manager Server. Check out the $RSAAM_HOME/server/servers/${MACHINE_NAME}_server/logs/${MACHINE_NAME}_server.out for details. Exiting."
	exit 1
fi
echo 
echo "Done"	

echo 
echo "Restarting the RSA Authentication Manager Servers..."
	
$RSAAM_HOME/server/rsaam restart allnoradius
 	
exec 5>&1
AMSTATUS=`$RSAAM_HOME/server/rsaam status allnoradius | tee >(cat - >&5)`
if [ `echo "$AMSTATUS" | grep "RUNNING" | wc -l` -lt 6 ]; then # 6 services must be running
 	echo -e "Something went wrong as the RSA AM failed to start with the replaced server certificate."
	echo -e "Now will try to revert the previous configuration.\n"
	# Stop RSA AM
	$RSAAM_HOME/server/rsaam stop allnoradius
	echo -e "Saving the configuration file with replaced certificate for further analysis to config_failed_replaced_cert_${NOW}.xml"
	cp $RSAAM_HOME/server/config/config.xml "$RSAAM_HOME/server/config/config_failed_replaced_cert_${NOW}.xml"
	# Restore a Weblogic config from the saved backup
	yes | cp -fr $BACKUP_FILENAME $RSAAM_HOME/server/config/config.xml 
	exec 5>&1
	AMSTATUS=`$RSAAM_HOME/server/rsaam start allnoradius | tee >(cat - >&5)`
	if [ `echo "$AMSTATUS" | grep "OK" | wc -l` -lt 6 ]; then # 6 services must be running
	     echo "Unable to start all RSA servers with the old configuration. Try to reboot the appliance. Exiting."
	fi
	exit 1
fi

echo "DONE. All RSA AM services are running. "

}

############################################################
# Delete a cert from all keystores
# Param 1: cert alias
delete_cert(){
	CERT_ALIAS=$1
	
	echo "Deleting $CERT_ALIAS from the  identity keystore "
	
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --delete --alias "$CERT_ALIAS" --keystore $RSAAM_HOME/server/security/root.jks -m $MASTER_PW --storepass $ROOT_STORE_PW
	
	echo "Deleting $CERT_ALIAS from the root keystore "

	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --delete --alias "$CERT_ALIAS" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW	
	
	echo "Deleting $CERT_ALIAS from the JDK keystore "

	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --delete --alias "$CERT_ALIAS" --keystore $RSAAM_HOME/appserver/jdk/jre/lib/security/cacerts -m $MASTER_PW --storepass "changeit"
	
	
}

############################################################
# Get keystore passwords
# 
get_passwords(){
	
read -s -p "Enter the Master Password: " MASTER_PW 
echo
#MASTER_PW="Twof0rt."  #fixed pass for testing
	
# Retriving keystore passwords
ID_STORE_PW=`$RSAAM_HOME/utils/rsautil manage-secrets --action get com.rsa.identity.store -m $MASTER_PW | grep com.rsa.identity.store |cut -d':' -f2`
if [ $? -ne 0 ]; then 
	echo "Exiting."
	exit 1 
fi

ROOT_STORE_PW=`$RSAAM_HOME/utils/rsautil manage-secrets --action get com.rsa.root.store -m $MASTER_PW | grep com.rsa.root.store |cut -d':' -f2`
		
}

############################################################
# List entries in all keystores 
# Param 1: cert alias. if empty them list all.

list_certs(){
local RETURNCODE=0

if [ "x$1" != "x" ]; then
  CERT_ALIAS="--alias $1"
	echo "Listing $MACHINE_NAME.jks"
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list  --alias "$1" --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW
	if [ $? -ne 0 ]; then
		RETURNCODE=1  		# return 1 if the alias is not in the server keystore
	fi	
	echo "Listing root.jks"
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list  --alias "$1" --keystore $RSAAM_HOME/server/security/root.jks -m $MASTER_PW --storepass $ROOT_STORE_PW
	# still return 0 (success) if the alias not in the root keystore 
  else
	echo "Listing $MACHINE_NAME.jks"
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW
	echo "Listing root.jks"
	$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list --keystore $RSAAM_HOME/server/security/root.jks -m $MASTER_PW --storepass $ROOT_STORE_PW
fi
return $RETURNCODE
}

############################################################
# Check if cert is already in keystores.
# Param 1: Cert file 
#
instore(){

CERTFILE=$1

	echo "Checking if the cert is already in keystores"
	
CERT_OWNER=`$RSAAM_HOME/appserver/jdk/bin/keytool -printcert -v -file "$CERTFILE" | grep "Owner:"`
RESOUT=`$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW | grep -B 1 "$CERT_OWNER"`

echo "$RESOUT" | grep "Certificate[1]" 
  if [ $? -eq 0 ]; then	
	if [ "`echo "$RESOUT" | sed 's/Certificate[1]: //'`" = "$CERT_OWNER" ]; then
		echo "Found in the $MACHINE_NAME.jks"
	fi
  fi
}

###########################################################
# Main
###########################################################

echo "######################################"
date
echo "Starting replace-cert.sh version $VER"
echo "######################################"

if [ "`whoami`" != "rsaadmin" ]; then
  echo "This script should be run as rsaadmin"
  exit 1
fi  

RSAAM_HOME="/usr/local/RSASecurity/RSAAuthenticationManager"
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $RSAAM_HOME/utils

# Setting RSA environment

. $RSAAM_HOME/utils/rsaenv

# Path to certificate files 
CERTSPATH="/tmp/"	

MACHINE_NAME=`hostname -s`
FQDN=`hostname`
echo
echo "Hostname: $MACHINE_NAME"
echo "FQDN: $FQDN"
echo

if [ $# -gt 0 ]; then
  if [ "$1" = "-delete" ]; then
	if [ -z "$2" ]; then usage && exit 1 
	fi  
	get_passwords
	delete_cert "$2"
    exit 0	 
#  elif [ "$1" = "-gencsr" ]; then
#	if [ -z "$2" ]; then usage && exit 1 
#	fi  
#    get_passwords
#    gencsr "$2"
#    exit 0
	elif [ "$1" = "-list" ]; then
	get_passwords
	list_certs "$2"
     exit 0	 	 
  elif [ "$1" = "-config" ]; then
	if [ -z "$2" ]; then usage && exit 1 
	fi
    get_passwords	
    configureServers "$2"
    exit 0
#  elif [ "$1" = "-instore" ]; then
#    get_passwords
#    instore "$2"
#    exit 0	
  fi
else usage && exit 1
fi

get_passwords

echo "com.rsa.identity.store: $ID_STORE_PW"
echo "com.rsa.root.store: $ROOT_STORE_PW"

#echo "Enter the alias for a new server certificate: "
#read ALIAS

ALIAS=$1

echo "Checking to see if the certificate alias ${ALIAS} exists."
$RSAAM_HOME/utils/rsautil manage-ssl-certificate --list --keystore $RSAAM_HOME/server/security/$MACHINE_NAME.jks -m $MASTER_PW --storepass $ID_STORE_PW | grep "$ALIAS"
	if [ $? -eq 1 ]; then
		gencsr
	else
		echo "Alias $ALIAS already exists."
	fi
		
echo "If you have received a reply from the CA make sure you have saved the server certificate, CA root certificate, and intermediate CA certificates (if any) into ${CERTSPATH}."
promptYesNo "Do you want to import certificates for the alias $ALIAS " y
	if [ $? -eq 0 ]; then
		echo "OK. Exiting."
		exit 1
	fi	
	
echo -e "\nFiles in the $CERTSPATH:\n"	
ls -1 ${CERTSPATH}
echo	
# File name of the Server certificate
echo "Enter a file name of the new server certificate:"
read CERTS[0] 

CERT_INFO=`openssl x509 -in "${CERTSPATH}${CERTS[0]}" -noout -subject -issuer -serial -dates `

echo -e "\n${CERT_INFO}\n"

#SRV_CERT_ISSUER=`openssl x509 -in "${CERTSPATH}${CERTS[0]}" -noout -issuer | sed 's/^issuer= //'`
SRV_CERT_ISSUER=`echo "${CERT_INFO}" | grep "issuer=" | sed 's/^issuer= //'`
SRV_CERT_SUBJECT=`echo "${CERT_INFO}" | grep "subject=" | sed 's/^subject= //'`

SRV_CERT_SIGALG=`openssl x509 -in "${CERTSPATH}${CERTS[0]}" -noout -text | grep -m 1 "Signature Algorithm:" | sed -e 's/^ *//g' -e 's/^Signature Algorithm: //'`
echo -e "Signature Algorithm = $SRV_CERT_SIGALG\n"
# check AM-26699 
if [ "$SRV_CERT_SIGALG" != "sha1WithRSAEncryption" ]; then 
	echo -e "Only sha1WithRSAEncryption signature algorithm supported. Exiting."
	exit 1
fi	

# Check to see if CN=<fqdn> 
openssl x509 -in "${CERTSPATH}${CERTS[0]}" -noout -subject | grep -e "CN=$FQDN"
    if [ $? -ne 0 ]; then
      echo "Wrong server certificate. Common Name (CN) of the server certificate must be $FQDN. Exiting."
      exit 1
    fi

FULLCHAIN=0  					# No full chain found
CERT_ISSUER=$SRV_CERT_ISSUER 	

i=1
while [ $FULLCHAIN -eq 0 ]; do
    echo -e "Files in the $CERTSPATH \n------------"
	echo -e "\nFiles in the $CERTSPATH:\n"	
	ls -1 ${CERTSPATH}
	echo	
    echo -e "------------"
    echo "Enter file name of the $CERT_ISSUER certificate:"
	read CERTS[$i]
	echo 
    echo -e "Details of the certificate ${CERTS[$i]}:\n------------"
	CERTINFO=`openssl x509 -in "${CERTSPATH}${CERTS[$i]}" -noout -subject -issuer -dates -serial`
	echo "$CERTINFO"
	C_SIGALG=`openssl x509 -in "${CERTSPATH}${CERTS[$i]}" -noout -text | grep -m 1 "Signature Algorithm:" | sed -e 's/^ *//g' -e 's/^Signature Algorithm: //'`
	echo -e "Signature Algorithm = $C_SIGALG"
    echo -e "------------"

	# check AM-26699 
	if [ "$C_SIGALG" != "sha1WithRSAEncryption" ]; then 
		echo -e "Only sha1WithRSAEncryption signature algorithm supported. Exiting."
		exit 1
	fi	
	C_ISSUER=`echo "$CERTINFO" | grep "issuer=" | sed 's/^issuer= //'`
	C_SUBJECT=`echo "$CERTINFO" | grep "subject=" | sed 's/^subject= //'`
	
	# Check the chain (if this Certificate is issuer of the previous certificate)
	if [ [ -n "$C_ISSUER" ] && [ -n "$C_SUBJECT" ] && [ "$CERT_ISSUER" = "$C_SUBJECT" ] ]; then
			echo -e "The certificate ${CERTS[0]} is signed by ${CERTS[$i]}.\nChecking if there is another CA in the chain ..." 
			# Check if the CA certificate is self signed, assuming that Root CA must be self signed
			if [ "$C_ISSUER" != "$C_SUBJECT" ]; then 
				echo -e "The ${CERTS[i]} does not seem to be Root CA certificate.\nThere should be another CA certificate in the chain."
				CERT_ISSUER=$C_ISSUER
				((i++))				
			else	
				echo -e "The ${CERTS[i]} is the Root CA certificate.\n"	
				echo -e "#######################################"
				echo -e "####### Done! Full chain found! #######" 
				echo -e "#######################################\n"	
				FULLCHAIN=1
			fi
	else 
		echo "${CERTS[$i]} is not issuer of ${CERTS[$i-1]}"
		promptYesNo "Do you have another CA certificate to try?" y
		if [ $? -eq 0 ]; then
			echo "Unable to build the full chain. Exiting."
			exit 1
		fi 	
	fi
done


for i in "${CERTS[@]}"
do    # List all the elements in the array.
  echo "${i}"
  echo "----------------------------------"
  openssl x509 -in "${CERTSPATH}${i}" -noout -subject -issuer -dates -serial
  echo -e "----------------------------------\n" ;
done

 
promptYesNo "Import the above certificates into the appliance?" y
	if [ $? -eq 0 ]; then
		echo "Exiting."
		exit 1
	fi 
		
# Checking some known issues
#
# check AM-26699
# 		
		
import_certs "$ALIAS"

list_certs "$ALIAS"

configureServers "$ALIAS"

  
echo "The certificate replacement successful."
