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

class LE {

	private
		$directory='https://acme-v01.api.letsencrypt.org/directory', // live
		//$directory='https://acme-staging.api.letsencrypt.org/directory', // staging
		$resources=null,
		$nonce='',
		$header,  // JOSE Header
		$account_key;
		
	protected
		$thumbprint,
		$acme_path='.well-known/acme-challenge/';
	
	public function __construct($account_key_pem){
		
		// load account key
		if (false===($this->account_key=openssl_pkey_get_private('file://'.$account_key_pem))){
			throw new Exception(
				'Could not load account key: '.$account_key_pem."\n".
				openssl_error_string()
			);
		}

		// get account key details
		if (false===($details=openssl_pkey_get_details($this->account_key))){
			throw new Exception(
				'Could not get account key details: '.$account_key_pem."\n".
				openssl_error_string()
			);
		}

		// JOSE Header - RFC7515
		$this->header=array(
			'alg'=>'RS256',
			'jwk'=>array( // JSON Web Key
				'e'=>$this->base64url($details['rsa']['e']), // public exponent
				'kty'=>'RSA',
				'n'=>$this->base64url($details['rsa']['n']) // public modulus
			)
		);

		// JSON Web Key (JWK) Thumbprint - RFC7638
		$this->thumbprint=$this->base64url(
			hash(
				'sha256',
				json_encode($this->header['jwk']),
				true
			)
		);	
	}
	
	public function __destruct(){
		if ($this->account_key) {
			openssl_pkey_free($this->account_key);
		}
	}	
	
	private function init(){
		$ret=$this->http_request($this->directory); // Read ACME Directory
		$this->resources=$ret['body']; // store resources for later use
		$this->nonce=$ret['headers']['replay-nonce']; // capture first replay-nonce
	}
	
	// Encapsulate $payload into JSON Web Signature (JWS) - RFC7515
	private function jws_encapsulate($payload){
		$protected=$this->header;
		$protected['nonce']=$this->nonce; // replay-nonce
		
		$protected64=$this->base64url(json_encode($protected));
		$payload64=$this->base64url(json_encode($payload));

		if (false===openssl_sign(
			$protected64.'.'.$payload64,
			$signature,
			$this->account_key,
			OPENSSL_ALGO_SHA256
		)){
			throw new Exception(
				'Failed to sign payload !'."\n".
				openssl_error_string()
			);
		}
		
		return array(
			'header'=>$this->header,
			'protected'=>$protected64,
			'payload'=>$payload64,
			'signature'=>$this->base64url($signature)
		);
	}
	
	// RFC7515 - Appendix C
	final protected function base64url($data){
		return rtrim(strtr(base64_encode($data),'+/','-_'),'=');
	}
	
	final protected function request($type,$payload=array(),$url=null,$raw=false,$accept=null){

		if ($this->resources===null){
			$this->init(); // read AMCE directory and get first replay-nonce
		}
		
		$data=json_encode(
			$this->jws_encapsulate(
				array_merge(
					$payload,
					array('resource'=>$type)
				)
			)
		);
		
		$ret=$this->http_request($url===null?$this->resources[$type]:$url,$data,$raw,$accept);
		
		$this->nonce=$ret['headers']['replay-nonce']; // capture replay-nonce
		return $ret;
	}
	
	final protected function http_request($url,$data=null,$raw=false,$accept=null){
		$ctx=stream_context_create(
			array(
				'http'=>array(
					'header'=>$data===null?'':'Content-Type: application/json',
					'method'=>$data===null?'GET':'POST',
					'user_agent'=>'CertLE (PHP LE Client)',
					'ignore_errors'=>true,
					'timeout'=>60,
					'content'=>$data
				)
			)
		);
		
		$body=@file_get_contents($url,false,$ctx);
		if ($body===false){
			throw new Exception('request error: '.$url);
		}
		
		list(,$code,$status)=explode(' ',reset($http_response_header),3);

		$headers=array_reduce( // parse http headers into array
			array_slice($http_response_header,1),
			function($carry,$item){
				list($k,$v)=explode(':',$item,2);
				
				$k=strtolower(trim($k));
				$v=trim($v);
				
				if ($k==='link'){ // parse Link Headers
					if (preg_match("/<(.*)>\\s*;\\s*rel=\"(.*)\"/",$v,$matches)){
						$carry['link'][$matches[2]]=$matches[1];
					}
				}else{
					$carry[$k]=$v;
				}
				
				return $carry;
			},
			array()
		);
	
		if (!$raw) {
			if ($body==''){
				$json='';
			}else{
				$json=json_decode($body,true);
			}
		}else{
			$json=null;
		}
		
		if ( ($code!=$accept) && ($code[0]!='2') ){
			if (is_array($json) && isset($json['detail'])){
				throw new Exception($json['detail']);
			}else{
				throw new Exception('request failed: '.$code.' ['.$status.']: '.$url);
			}
		}
		
		if (!$raw) {
			if ($json===null) {
				throw new Exception('json_decode failed: '.print_r($headers,true).$body);
			}else{
				$body=$json;
			}		
		}
		
		$ret=array(
			'code'=>$code,
			'status'=>$status,
			'headers'=>$headers,
			'body'=>$body
		);
		
		//print_r($ret);
		
		return $ret;
	}

	final protected function write_challenge($docroot,$challenge){
		if (!is_dir($docroot)){
			throw new Exception('docroot does not exist: '.$docroot);
		}

		@mkdir($docroot.$this->acme_path,0755,true);
		
		if (!is_dir($docroot.$this->acme_path)){
			throw new Exception('failed to create acme challenge directory: '.$docroot.$this->acme_path);
		}
		
		$keyAuthorization=$challenge['token'].'.'.$this->thumbprint;
		
		if (false===@file_put_contents($docroot.$this->acme_path.$challenge['token'],$keyAuthorization)){
			throw new Exception('failed to create challenge file: '.$docroot.$this->acme_path.$challenge['token']);
		}
	}
	
	final protected function remove_challenge($docroot,$challenge){
		unlink($docroot.$this->acme_path.$challenge['token']);
		rmdir($docroot.$this->acme_path);
		rmdir($docroot.dirname($this->acme_path));
	}
	
	final protected function pem2der($pem) {
		return base64_decode(
			implode(
				'',
				array_slice(
					array_map('trim',explode("\n",trim($pem))),
					1,
					-1
				)
			)
		);
	}
	
	final protected function der2pem($der) {
		return "-----BEGIN CERTIFICATE-----\n".
			chunk_split(base64_encode($der),64,"\n").
			"-----END CERTIFICATE-----\n";
	}
	
	final protected function generate_csr($domain_key_pem,$domains){
		
		if (false===($domain_key=openssl_pkey_get_private('file://'.$domain_key_pem))){
			throw new Exception(
				'Could not load domain key: '.$domain_key_pem."\n".
				openssl_error_string()
			);
		}
				
		if (false===($fn=tempnam("/tmp", "CNF_"))){
			throw new Exception('Failed to create temp file !');
		}

		if (false===@file_put_contents($fn,
			'HOME = .'."\n".
			'RANDFILE=$ENV::HOME/.rnd'."\n".
			'[req]'."\n".
			'distinguished_name=req_distinguished_name'."\n".
			'[req_distinguished_name]'."\n".
			'[v3_req]'."\n".
			'[v3_ca]'."\n".
			'[SAN]'."\n".
			'subjectAltName='.
			implode(',',array_map(function($domain){
				return 'DNS:'.$domain;
			},$domains)).
			"\n"
		)){
			throw new Exception('Failed to write tmp file: '.$fn);
		}

		$dn=array('commonName'=>reset($domains));
		
		$csr=openssl_csr_new($dn,$domain_key,array(
			'config'=>$fn,
			'req_extensions'=>'SAN',
			'digest_alg'=>'sha512'
		));

		unlink($fn);
		openssl_pkey_free($domain_key);
		
		if (!$csr) {
			throw new Exception(
				'Could not generate CSR !'."\n".
				openssl_error_string()
			);
		}
		
		if (false===openssl_csr_export($csr,$out)){
			throw new Exception(
				'Could not export CSR !'."\n".
				openssl_error_string()
			);
		}
		
		return $out;
	}	
}
