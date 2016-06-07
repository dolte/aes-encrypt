package com.dolte.encrypt;

import java.nio.charset.Charset;
import java.security.KeyPair;

import com.dolte.encrypt.pki.PkiFactory;
import com.dolte.encrypt.pki.StringKeyPair;

/**
 * 암호화 유틸 
 * 
 * <pre>
 * 암호화 유틸
 * </pre>
 */
public class Encryptor {
	public static final String PUBLIC_KEY = "ALGORITHM_PKI";
	public static final String SYMMETRIC_KEY = "SYMMETRIC_KEY";
	public static final String HASH_KEY = "HASH_KEY";
	
	private static boolean initailized = false;
	private static String SYNC = "";

	private static void init() {
	}
	
	
	public static KeyPair getPkiKeyPair() {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return PkiFactory.getInstance().getKeyPair();
	}
	

	public static StringKeyPair getStringKeyPair() {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return new StringKeyPair(PkiFactory.getInstance().getKeyPair());
	}
	
	public static byte[] encryptPki(String publicKey, byte[] src) {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return PkiFactory.getInstance().encrypt(publicKey, src);
	}
	public static String encryptPki(String publicKey, String src) {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return Base64Utils.encodeAsString(encryptPki(publicKey, src.getBytes(getCharset())));
	}
	
	public static byte[] decryptPki(String privateKey, byte[] src) {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return PkiFactory.getInstance().decrypt(privateKey, src);
	}
	public static String decryptPki(String privateKey, String src) {
		synchronized (SYNC) {
			if(!initailized) {
				init();
			}
		}
		return new String(PkiFactory.getInstance().decrypt(privateKey, Base64Utils.decode(src)));
	}
	
	public static Charset getCharset() {
		String charsetName = EncryptProperty.getProperty("charset.name");
		if(charsetName == null || charsetName.trim().equals("")) {
			return Charset.defaultCharset(); 
		}
		return Charset.forName(charsetName);
	}
}
