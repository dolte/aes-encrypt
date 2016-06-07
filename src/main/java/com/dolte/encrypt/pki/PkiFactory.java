package com.dolte.encrypt.pki;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import com.dolte.encrypt.Base64Utils;
import com.dolte.encrypt.EncryptLogger;
import com.dolte.encrypt.EncryptProperty;


/**
 * Public Key Encryption Factory
 * 
 * <pre>
 * 공개키 암호화 모듈 Factory
 * </pre>
 */
public class PkiFactory {

	private final SecureRandom random = new SecureRandom();
	protected KeyPairGenerator publicKeyGenerator;
	private final String KEYPAIR_HOLDER = ""; 
	private KeyPair keyPair;
	private String providerClassName;
	private String providerName;
	private String algorithm;
	private String simpleAlgorithm;
	private int bitLength;
	private int textLength;
	private String publicDecryptorYn;
	private KeyFactory keyFactory;
	
	private static class SingletonHolder {
		private static final PkiFactory instance = new PkiFactory(); 
	}
	
	public static PkiFactory getInstance() {
		return SingletonHolder.instance;
	}
	
	public PkiFactory() {
		publicDecryptorYn = EncryptProperty.getProperty("public.decryptor.yn");
		
		if(!"Y".equals(publicDecryptorYn)) {
			publicDecryptorYn = "N";
		} 
		
		preparingAlgorithm();
		if("Y".equals(publicDecryptorYn)) {
			loadKeyGenerator();
			runKeyGenerator();
		}
		loadKeyFactory();
		
	}

	private void loadKeyFactory() {
		try {
			keyFactory = KeyFactory.getInstance(simpleAlgorithm);
		} catch (NoSuchAlgorithmException e) {
			String errMsg = simpleAlgorithm + " is invalid algorithm. Check " + EncryptProperty.getPropertiesFileName();
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);		
		}
	}

	private void preparingAlgorithm() {
		algorithm = EncryptProperty.getProperty("public.algorithm.name");
		
		if(algorithm == null || algorithm.trim().equals("")) {
			EncryptLogger.error("Public key encryption algorithm not found. Cannot use public key encryptor. Check " + EncryptProperty.getPropertiesFileName());
			return;
		}
		
		if(algorithm.indexOf("/") < 0) {
			simpleAlgorithm = algorithm;
		} else {
			simpleAlgorithm = algorithm.substring(0, algorithm.indexOf("/"));
		}
		
	}

	private void loadKeyGenerator() {
		bitLength = 0;
		textLength = 256;
		try {
			bitLength = Integer.parseInt(EncryptProperty.getProperty("public.algorithm.bit"));
			textLength = bitLength / 16;
		} catch(Exception e) {
			EncryptLogger.error("Public key encryption bit length invaldid. Cannot use public key encryptor. Check " + EncryptProperty.getPropertiesFileName());
			return;
		}

		providerClassName = EncryptProperty.getProperty("public.algorithm.provider.class");
		providerName = EncryptProperty.getProperty("public.algorithm.provider.name");
		
		if(providerClassName != null && !providerClassName.trim().equals("")) {
			try {
				Class providerClazz = Class.forName(providerClassName);
				if(Provider.class.isAssignableFrom(providerClazz)) {
					Security.addProvider((Provider) providerClazz.newInstance());
				} else {
					EncryptLogger.info("[" + providerClassName + "] must extends java.security.Provider");
				}
			} catch (ClassNotFoundException e) {
				EncryptLogger.error("Security provider class [" + providerClassName + "] not found.", e);
			} catch (InstantiationException e) {
				EncryptLogger.error("Security provider class [" + providerClassName + "] instatiation failed.", e);
			} catch (IllegalAccessException e) {
				EncryptLogger.error("Security provider class [" + providerClassName + "] instatiation failed.", e);
			}
			
		}
		
		
		try {
			if(providerName == null || providerName.trim().equals("")) {
				publicKeyGenerator = KeyPairGenerator.getInstance(simpleAlgorithm);
			} else {
				publicKeyGenerator = KeyPairGenerator.getInstance(simpleAlgorithm, providerName);
			}
		} catch (NoSuchAlgorithmException e) {
			EncryptLogger.error("[" + algorithm + "] is invalid encryption algorithm. Cannot use public key encryptor. Check " + EncryptProperty.getPropertiesFileName());
			return;
		} catch (NoSuchProviderException e) {
			EncryptLogger.error("[" + algorithm + "] is not support provider '" + providerName + "' Check " +  EncryptProperty.getPropertiesFileName());
			return;
		}
		
		long start = System.currentTimeMillis();
		long end;
		publicKeyGenerator.initialize(bitLength);
		end = System.currentTimeMillis();
		EncryptLogger.debug("Initialed - " + (end - start));
		start = end;
		
	}
	
	private void runKeyGenerator() {
		generateKeyPair();
		Thread t = new Thread(new Runnable() {
			
			public void run() {
				long intervalSec = 600;

				try {
					intervalSec = Long.parseLong(EncryptProperty.getProperty("public.key.generate.secs"));
				} catch (NumberFormatException nfe) {
					;
				}
				
				while(true) {
					try {
						Thread.sleep(intervalSec * 1000);
						generateKeyPair();
					} catch (InterruptedException e) {
						;
					}
				}
			}
		});
		
		t.start();
	}

	protected void generateKeyPair() {
		KeyPair newKeyPair = publicKeyGenerator.generateKeyPair();
		synchronized (KEYPAIR_HOLDER) {
			keyPair = newKeyPair;
		}
	}
	
	protected KeyPairGenerator getPublicKeyGenerator() {
		return publicKeyGenerator;
	}
	
	public KeyPair getKeyPair() {
		if(keyPair == null) {
			synchronized (KEYPAIR_HOLDER) {
				generateKeyPair();
			}
		}
		synchronized (KEYPAIR_HOLDER) {
			return keyPair;
		}
	}
	
	public byte[] encrypt(String publicKey, byte[] src) {
		byte[] publicBytes = Base64Utils.decode(publicKey);
		X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicBytes);

		PublicKey pubKey;
		try {
			pubKey = keyFactory.generatePublic(keySpec);
		} catch (InvalidKeySpecException e) {
			String errMsg = " Invalid public key.";
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		}
		return encrypt(pubKey, src);
	}
	
	public byte[] decrypt(String privateKey, byte[] src) {
		byte[] privateBytes = Base64Utils.decode(privateKey);
		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privateBytes);

		PrivateKey privKey;
		try {
			privKey = keyFactory.generatePrivate(keySpec);
		} catch (InvalidKeySpecException e) {
			String errMsg = " Invalid private key.";
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		}
		return decrypt(privKey, src);
	}
	
	public byte[] encrypt(PublicKey key, byte[] src) {
//		byte[] bytes = new byte[src.length];
		EncryptLogger.debug("Orginal size = " + src.length);
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		Cipher cipher = makeChipher(Cipher.ENCRYPT_MODE, key);
		
		try {
			for(int i = 0; i < src.length; i+=textLength) {
				int length = i + textLength < src.length ? textLength : src.length - i;
//				System.arraycopy(cipher.doFinal(src, i, length), 0, bytes, i, length);
				byte[] block = Arrays.copyOfRange(src, i, i + length);
//				System.err.println(i + "," + length + "," +src.length + "," + block.length+"-"+new String(block));
				System.err.println("ENC TOKEN = " + new String(block));
				stream.write(cipher.doFinal(block));
//				System.err.println("SIZE:" + block.length + " TO " + stream.toByteArray().length);
				System.err.println(Base64Utils.encodeAsString(new String(stream.toByteArray())));
			}
//			ScuEncryptLogger.debug("Enc size = " + bytes.length);
//			return bytes;
//			return cipher.doFinal(src);
			return stream.toByteArray();
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public byte[] decrypt(PrivateKey key, byte[] src) {
		if(!"Y".equals(publicDecryptorYn)) {
			throw new RuntimeException("Cannot decrypt on this system");
		}
//		byte[] bytes = new byte[src.length];
		System.err.println("DEC SRC SIZE="+src.length);
		ByteArrayOutputStream stream = new ByteArrayOutputStream();
		Cipher cipher = makeChipher(Cipher.DECRYPT_MODE, key);
		try {
//			return cipher.doFinal(src);
			for(int i = 0; i < src.length; i+=(textLength*2)) {
				int length = i + (textLength*2) < src.length ? (textLength*2) : src.length - i;
//				System.err.println(i + "," + length + "," +src.length);
				byte[] block = Arrays.copyOfRange(src, i, i + length);
				byte[] token = cipher.doFinal(block);
				System.err.println("DEC TOKEN = " + new String(token));
				stream.write(token);
//				System.arraycopy(token, 0, bytes, i, token.length);
			}
//			return cipher.doFinal(src);
			return stream.toByteArray();
		} catch (IllegalBlockSizeException e) {
			throw new RuntimeException(e);
		} catch (BadPaddingException e) {
			throw new RuntimeException(e);
		} catch (IOException e) {
			throw new RuntimeException(e);
		}
	}
	
	public Cipher makeChipher(int cipherMode, Key key) {
		Cipher cipher;
		try {
			if (providerName != null && !providerName.trim().equals("")) {
				cipher = Cipher.getInstance(simpleAlgorithm, providerName);
			} else {
				cipher = Cipher.getInstance(simpleAlgorithm);
			}
		    if(cipherMode == Cipher.ENCRYPT_MODE) {
		    	cipher.init(Cipher.ENCRYPT_MODE, key, random); 
		    } else {
		    	cipher.init(Cipher.DECRYPT_MODE, key);
		    }
		} catch (NoSuchAlgorithmException e) {
			String errMsg = simpleAlgorithm + " is invalid algorithm. Check " + EncryptProperty.getPropertiesFileName();
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		} catch (NoSuchProviderException e) {
			String errMsg = simpleAlgorithm + " is invalid algorithm. Check " + EncryptProperty.getPropertiesFileName();
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		} catch (NoSuchPaddingException e) {
			String errMsg = simpleAlgorithm + " is invalid algorithm. Check " + EncryptProperty.getPropertiesFileName();
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		} catch (InvalidKeyException e) {
			String errMsg = " Invalid public or private key.";
			EncryptLogger.error(errMsg, e);
			throw new RuntimeException(errMsg, e);
		}
		
		return cipher;
	}
	
	public KeyFactory getKeyFactory() {
		return keyFactory;
	}
}
