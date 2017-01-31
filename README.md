# CertLE
A Let's Encrypt PHP Command Line ACME Client

### Usage

  	certle SUBCOMMAND

		SUBCOMMANDS: (All keys are in PEM-Format)
		
			genrsa <bits>                              Generate new RSA-Key
				 <bits>         RSA-Key size in bits (default: 2048)
				
			register <account_key> <email>             Register key with ACME-Server
			auto-register <account_key> <email>        Same as above but auto-accepts TOS
				 <account_key>  Account-Key
				 <email>        Contact E-Mail
		
			cert <account_key> <domain_key> options    Issue Certificate
				 <account_key>  Account-Key
				 <domain_key>   Private-Key (public part of key is used to generate CSR)
				  
				options:
				 -w, --webroot  Path to webroot/docroot
				                must be specified in front of -d, --domain; can be repeated
				                for each domain otherwise the previous one is used
				 -d, --domain   Domainname
				                can be repeated up to 100 times
				 --cert         Output Certificate
				 --chain        Output Intermediate CA Certificate
				 --fullchain    Output cert + chain
				 --csr          Output CSR

			revoke <key> <cert>                        Revoke Certificate
				 <key>          Acount-Key or Domain-Key
				 <cert>         cert or fullchain

			deactivate <account_key> <account_id>      Deactivate Account
				 <account_key>  Account-Key
				 <account_id>   Account ID (URL)
				                this URL is displayed when running the 'register' subcommand

### Examples

###### Generate an Account-Key in PEM-Format:

    ./certle genrsa 4096 > account_key.pem
    
###### Register Account-Key with Let's Encrypt ACME-Server

    ./certle register account_key.pem contact@example.com

###### Get Certificate / Renew Certificate

    ./certle cert account_key.pem domain_key.pem \
    	-w /var/www/example.com/ \
    	-d example.com \
    	-d www.example.com \
    	--csr csr.pem \
    	--cert cert.pem \
    	--chain chain.pem \
    	--fullchain fullchain.pem

###### Revoke Certificate

    ./certle revoke account_key.pem cert.pem

###### Deactivate Account

    ./certle deactivate account_key.pem https://acme-v01.api.letsencrypt.org/acme/reg/xxxxx



> CertLE - A Let's Encrypt PHP Command Line ACME Client
Copyright (C) 2016  S.Körfgen

> This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

> This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

> You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
