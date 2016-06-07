package com.dolte.encrypt;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

import org.bouncycastle.util.encoders.Base64Encoder;

public class Base64Utils {
	public static String encodeAsString(String src) {
		byte[] bytes = src.getBytes(StandardCharsets.ISO_8859_1);
		return encodeAsString(bytes);
	}

	public static String encodeAsString(byte[] bytes) {
		return new String(encode(bytes), StandardCharsets.ISO_8859_1);
	}

	public static byte[] encode(String src) {
		byte[] bytes = src.getBytes(StandardCharsets.ISO_8859_1);
		return encode(bytes);
	}

	public static byte[] encode(byte[] bytes) {
		Base64Encoder encoder = new Base64Encoder();
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		try {
			encoder.encode(bytes, 0, bytes.length, bs);
			return bs.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("Cannot encode BASE64 stream.", e);
		}
	}

	public static String decodeAsString(String src) {
		byte[] bytes = src.getBytes(StandardCharsets.ISO_8859_1);
		return decodeAsString(bytes);
	}

	public static String decodeAsString(byte[] bytes) {
		return new String(decode(bytes), StandardCharsets.ISO_8859_1);
	}
	
	public static byte[] decode(String src) {
		byte[] bytes = src.getBytes(StandardCharsets.ISO_8859_1);
		return decode(bytes);
	}


	public static byte[] decode(byte[] bytes) {
		Base64Encoder decoder = new Base64Encoder();
		ByteArrayOutputStream bs = new ByteArrayOutputStream();
		try {
			decoder.decode(bytes, 0, bytes.length, bs);
			return bs.toByteArray();
		} catch (IOException e) {
			throw new RuntimeException("Cannot decode BASE64 stream.", e);
		}
	}

}
