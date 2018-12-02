<?php
/*
	CertLE - A Let's Encrypt PHP Command Line ACME Client
	Copyright (C) 2016  S.Körfgen

	This program is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	This program is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

set_time_limit(0);

require('CertLE.inc.php');

function exception_handler($e){
	$err=error_get_last();
	echo 'Error: '.$e->getMessage()."\n".($err['message']?$err['message']."\n":'');
	exit(1);	
}

set_exception_handler('exception_handler');

if (!extension_loaded('openssl')) {
	throw new Exception('PHP OpenSSL Extension is required but not installed/loaded !');
}

function get_args($offset) {
	global $argv;
	
	$lists=array(array(),array());
	foreach(array_slice($argv,$offset) as $idx=>$item){
		$lists[$idx%2==0?0:1][]=$item;
	}
	$out=array();
	foreach($lists[0] as $k=>$v){
		$o=isset($lists[1][$k])?$lists[1][$k]:null;
		$out[]=array(ltrim($v,'-')=>$o);
	}
	return $out;
}

if (isset($argv[1])){
	switch($argv[1]) {
		case 'genrsa':
			$bits=2048;
			
			if (isset($argv[2])){
				$bits=intval($argv[2]);
			}

			if (false===($fn=tempnam(sys_get_temp_dir(), "CNF_"))){
				throw new Exception('Failed to create temp file !');
			}
			
			if (false===@file_put_contents($fn,
				'HOME = .'."\n".
				'RANDFILE=$ENV::HOME/.rnd'."\n".
				'[v3_ca]'."\n"
			)){
				throw new Exception('Failed to write tmp file: '.$fn);
			}
			
			$config=array(
				'config'=>$fn,
				'private_key_bits'=>$bits,
				'private_key_type'=>OPENSSL_KEYTYPE_RSA,
			);

			$key=openssl_pkey_new($config);
			openssl_pkey_export($key,$pem,null,$config);
			unlink($fn);
			echo $pem;		
		break;
		case 'register':
			if (!isset($argv[2])){
				throw new Exception('Account-Key expected !');
			}
	
			$certLE=new CertLE($argv[2]);
			$certLE->register(isset($argv[3])?$argv[3]:null);
		break;
		case 'auto-register':
			if (!isset($argv[2])){
				throw new Exception('Account-Key expected !');
			}
			
			$certLE=new CertLE($argv[2]);
			$certLE->register(isset($argv[3])?$argv[3]:null,true);
		break;
		case 'cert':
			if (!isset($argv[2])){
				throw new Exception('Account-Key expected !');
			}
			
			if (!isset($argv[3])){
				throw new Exception('Domain-Key expected !');
			}
			
			$args=get_args(4);
			$opts=array();
			$webroot=null;
			$domains=array();

			foreach($args as $item){
				$value=reset($item);
				$arg=key($item);
				switch($arg){
					case 'webroot':
					case 'w':
						$webroot=rtrim($value,'/').'/';
					break;
					case 'domain':
					case 'd':
						if ($webroot===null) {
							throw new Exception('-w, --webroot must be specified in front of -d, --domain !');
						}
						$domains[$value]=$webroot;
					break;
					case 'csr':
					case 'cert':
					case 'chain':
					case 'fullchain':
						$opts[$arg]=$value;
					break;
					default:
						throw new Exception('Unknown Parameter: '.$arg);
					break;
				}
			}
			if ($webroot===null){
				throw new Exception('-w , --webroot parameter missing !');
			}
			if (empty($domains)){
				throw new Exception('-d , --domain parameter missing !');
			}

			if ( (!isset($opts['cert'])) && (!isset($opts['fullchain'])) ) {
				throw new Exception('--cert or --fullchain parameter missing !');
			}
			
			$certLE=new CertLE($argv[2]);
	
			$ret=$certLE->get_cert(
				$argv[3],
				$domains,
				$opts
			);
		break;
		case 'revoke':
			if (!isset($argv[2])){
				throw new Exception('Account-Key or Domain-Key expected !');
			}
			
			if (!isset($argv[3])){
				throw new Exception('Cert or Fullchain expected !');
			}
			
			$certLE=new CertLE($argv[2]);
			$certLE->revoke($argv[3]);
		break;
		case 'deactivate':
			if (!isset($argv[2])){
				throw new Exception('Account-Key expected !');
			}
			if (!isset($argv[3])){
				throw new Exception('Account-ID (URL) expected !');
			}

			$certLE=new CertLE($argv[2]);
			$certLE->deactivate($argv[3]);
		break;
		default:
			throw new Exception('Unknown subcommand: '.$argv[1]);
		break;
	}
}else{
echo <<<EOD
CertLE - Let's Encrypt PHP Command Line ACME Client
Copyright (C) 2016  S.Körfgen

 Usage:
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


EOD;
}
