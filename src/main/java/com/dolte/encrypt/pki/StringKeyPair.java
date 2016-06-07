package com.dolte.encrypt.pki;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import com.dolte.encrypt.Base64Utils;
import com.dolte.encrypt.EncryptLogger;

public class StringKeyPair {
	private String publicKey;
	private String privateKey;
	
	public StringKeyPair(String publicKey, String privateKey) {
		this.publicKey = publicKey;
		this.privateKey = privateKey;
	}
	
	
	
	public StringKeyPair(PublicKey pubKey, PrivateKey privKey) {
		
		this.publicKey = Base64Utils.encodeAsString(pubKey.getEncoded());
		this.privateKey = Base64Utils.encodeAsString(privKey.getEncoded());
	}

	public StringKeyPair(KeyPair keyPair) {
		this(keyPair.getPublic(), keyPair.getPrivate());
	}

	public String getPublicKey() {
		return publicKey;
	}
	public void setPublicKey(String publicKey) {
		this.publicKey = publicKey;
	}
	public String getPrivateKey() {
		return privateKey;
	}
	public void setPrivateKey(String privateKey) {
		this.privateKey = privateKey;
	}
	
	public KeyPair toKeyPair() {
		KeyFactory factory = PkiFactory.getInstance().getKeyFactory();
		
		X509EncodedKeySpec publicSpec = new X509EncodedKeySpec(Base64Utils.decode(publicKey));
		PublicKey pubKey;
		try {
			pubKey = factory.generatePublic(publicSpec);
		} catch (InvalidKeySpecException e) {
			String msg = "Invalid public key [" + this.publicKey + "]";
			EncryptLogger.error(msg, e);
			throw new RuntimeException(msg, e);
		}
		
		X509EncodedKeySpec privateSpec = new X509EncodedKeySpec(Base64Utils.decode(privateKey));
		PrivateKey privKey;
		try {
			privKey = factory.generatePrivate(privateSpec);
		} catch (InvalidKeySpecException e) {
			String msg = "Invalid public key [" + this.publicKey + "]";
			EncryptLogger.error(msg, e);
			throw new RuntimeException(msg, e);
		}
		KeyPair keyPair = new KeyPair(pubKey, privKey);
		return keyPair;
	}
}
