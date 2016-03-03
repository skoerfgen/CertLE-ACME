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

require('LE.inc.php');

class CertLE extends LE {

	public function register($email=null,$auto=false){
		$data=$email?
			array('contact'=>array('mailto:'.$email)):
			array();
		
		$ret=$this->request('new-reg',$data,null,false,409);
		
		switch($ret['code']){
			case 409: // account already registered
				$reg=$ret['headers']['location'];
				$ret=$this->request('reg',$data,$reg);
			break;
			case 201: // account created
				$reg=$ret['headers']['location'];
				echo 'Account created !'."\n";
			break;
			default:
				throw new Exception('register error: '.$ret['body']['detail']);
			break;
		}
		
		echo 'Account ID: '.$ret['body']['id']."\n";
		echo 'Created at: '.$ret['body']['createdAt']."\n";
		
		if (!isset($ret['body']['contact'])){
			echo 'Contact: NOT SET !'."\n";
		}else{
			echo 'Contact: '.implode(', ',$ret['body']['contact'])."\n";
		}
		
		if ( !isset($ret['body']['agreement']) ){
			echo 'Terms of Service: '."\n\t".$ret['headers']['link']['terms-of-service']."\n";
			if ($auto || ('y'==strtolower(readline('Agree? [y/N] ')))){
				echo 'Updating Agreement..';
				$data['agreement']=$ret['headers']['link']['terms-of-service'];
				$ret=$this->request('reg',$data,$reg);
				echo 'OK'."\n";
			}
		}
	}

	public function get_cert($domain_key_pem,$domains,$opts){
		$this->check_output_writable($opts); // check if output files are writable
		$this->simulate_challenges($domains);
		
		echo 'Validating domains: '."\n";
		
		foreach($domains as $domain=>$docroot){
			echo ' Validating: '.$domain.'..';
			$ret=$this->request('new-authz',array(
				'identifier'=>array(
					'type'=>'dns',
					'value'=>$domain
				)
			));
			
			if ($ret['code']!=201){
				throw new Exception('unexpected http status code: '.$ret['code']);
			}
			
			// find http-01 in list of challenges
			$challenge=reset(array_filter($ret['body']['challenges'],function($o){
				return $o['type']==='http-01'; 
			}));
			
			if (empty($challenge)) throw new Exception('http-01 challenge not found !');
			
			$this->write_challenge($docroot,$challenge);
			
			// notify ACME-Server that challenge file has been placed
			$ret=$this->request(
				'challenge',
				array(
					'keyAuthorization'=>$challenge['token'].'.'.$this->thumbprint
				),
				$challenge['uri']
			);
			
			if ($ret['code']!=202) { // HTTP: Accepted
				$this->remove_challenge($docroot,$challenge);
				throw new Exception('unexpected http status code: '.$ret['code']);
			}
			
			echo '.';
			sleep(3); // waiting for ACME-Server to verify challenge
			
			// poll
			$tries=10;
			$delay=2;
			do {
				$ret=$this->http_request($challenge['uri']);
				if ($ret['body']['status']==='valid'){
					break;
				}
				echo '.';
				sleep($delay); // still waiting..
				$delay=min($delay*2,32);
				if (--$tries==0) {
					$this->remove_challenge($docroot,$challenge);
					throw new Exception('Failed to verify challenge after 10 tries !');
				}
			} while($ret['body']['status']==='pending');
			
			$this->remove_challenge($docroot,$challenge);
			
			if ($ret['body']['status']!=='valid') {
				throw new Exception('Challenge failed');
			}
			
			
			echo 'OK';
			
			if (
				isset($ret['body']['validationRecord']) &&
				is_array($ret['body']['validationRecord'])
			){
				$tmp=reset($ret['body']['validationRecord']);
				if (isset($tmp['addressUsed'])){
					echo ' ['.$tmp['addressUsed'].']';
				}
				
			}
			
			echo "\n";
		}
		
		echo 'Generating Certificate Signing Request (CSR)...';
		$csr=$this->generate_csr($domain_key_pem,array_keys($domains));
		echo 'OK'."\n";		
		
		echo 'Requesting Certificate...';
		$ret=$this->request('new-cert',array(
			'csr'=>$this->base64url($this->pem2der($csr))
		),null,true);
		
		if ($ret['code']!=201) { // HTTP: Created
			throw new Exception('unexpected http status code: '.$ret['code']);
		}
		
		if ($ret['headers']['content-type']!='application/pkix-cert') {
			throw new Error('unexpected content-type: '.$ret['headers']['content-type']);
		}
		
		echo 'OK'."\n";
		
		$cert=$this->der2pem($ret['body']);
		
		if (isset($opts['chain']) || isset($opts['fullchain'])){
			echo 'Requesting Intermediate CA Certificate...';
			if (isset($opts['chain']) || isset($opts['fullchain'])){
				$ret=$this->http_request($ret['headers']['link']['up'],null,true);

				if ($ret['code']!=200){
					throw new Exception('unexpected http status code: '.$ret['code']);
				}
				
				if ($ret['headers']['content-type']!='application/pkix-cert') {
					throw new Error('unexpected content-type: '.$ret['headers']['content-type']);
				}

				$intermediate=$this->der2pem($ret['body']);
			}
			echo 'OK'."\n";		
		}
		
		echo "\n";
		
		if (isset($opts['fullchain'])){
			if (false===@file_put_contents($opts['fullchain'],$cert.$intermediate)){
				throw new Exception('Failed to write fullchain to: '.$opts['fullchain']);
			}else{
				echo '  Saved Fullchain to: '.$opts['fullchain']."\n";
			}
		}
		
		if (isset($opts['cert'])){
			if (false===@file_put_contents($opts['cert'],$cert)){
				throw new Exception('Failed to write cert to: '.$opts['cert']);
			}else{
				echo 'Saved Certificate to: '.$opts['cert']."\n";
			}
		}

		if (isset($opts['chain'])){
			if (false===@file_put_contents($opts['chain'],$intermediate)){
				throw new Exception('Failed to write chain to: '.$opts['chain']);
			}else{
				echo '      Saved Chain to: '.$opts['chain']."\n";
			}
		}
				
		if (isset($opts['csr'])){
			if (false===@file_put_contents($opts['csr'],$csr)){
				throw new Exception('Failed to write csr to: '.$opts['csr']);
			}else{
				echo '        Saved CSR to: '.$opts['csr']."\n";
			}
		}
	}
	
	public function revoke($fn_cert){
		if (false===($data=@file_get_contents($fn_cert))){
			throw new Exception('Failed to open cert: '.$fn_cert);	
		}
	
		if (false===($x509=@openssl_x509_read($data))){
			throw new Exception('Failed to parse cert: '.$fn_cert."\n".openssl_error_string());
		}
		
		if (false===(@openssl_x509_export($x509,$cert))){
			throw new Exception('Failed to parse cert: '.$fn_cert."\n".openssl_error_string());
		}

		$cert=$this->base64url($this->pem2der($cert));
		
		$ret=$this->request('revoke-cert',array('certificate'=>$cert));
		if ($ret['code']==200) {
			echo 'Certificate revoked !'."\n";
		} else {
			throw new Exception('unexpected http status code: '.$ret['code']);
		}
	}
	
	private function simulate_challenges($domains){
		echo 'Simulating challenges: '."\n";
		$token=uniqid();
		$challenge=array('token'=>$token);
		foreach($domains as $domain=>$docroot){
			echo '    Testing: '.$domain.'...';
			$this->write_challenge($docroot,$challenge);
			try {
				$ret=$this->http_request('http://'.$domain.'/'.$this->acme_path.$challenge['token'],null,true);
				usleep(500000);
			}catch(Exception $e){
				throw $e;
			}finally{
				$this->remove_challenge($docroot,$challenge);
			}
			if ($ret['body']!=$token.'.'.$this->thumbprint){
				throw new Exception('Failed to verify challenge file contents !');
			}
			echo 'OK'."\n";
		}
	}
	
	private function check_output_writable($opts){
		foreach($opts as $type=>$fn){
			if (!is_writable(file_exists($fn)?$fn:dirname($fn))) {
				throw new Exception('Output file is not writable ('.$type.'): '.$fn);
			}
		}
	}
	
}
