package com.dolte.encrypt;

import java.io.IOException;
import java.io.InputStream;
import java.util.Properties;

public class EncryptProperty {
	public static final String DEFAULT_PROPERTIES_FILENAME = "encrypt.properties";
	
	public static final String PROP_CHARSET_NAME = "charset.name";
	public static final String PROP_LOGGER_LEVEL = "logger.level";

	public static final String PROP_PUBLIC_ALGORITHM_NAME = "public.algorithm.name";
	public static final String PROP_PUBLIC_ALGORITHM_BIT = "public.algorithm.bit";
	public static final String PROP_PUBLIC_ALGORITHM_PROVIDER_NAME = "public.algorithm.provider.name";
	public static final String PROP_PUBLIC_ALGORITHM_PROVIDER_CLASS = "public.algorithm.provider.class";
	public static final String PROP_PUBLIC_KEY_GENERATE_SECS = "public.key.generate.secs";
	public static final String PROP_PUBLIC_DECRYPTOR_YN = "public.decryptor.yn";

	private static Properties properties;
	private static String propertiesFileName;

	
	public static String getProperty(String key) {
		if(properties == null) {
			properties = new Properties();
			loadProperties();
		}
		
		return properties.getProperty(key);
	}
	
	public static void setProperty(String key, String value) {
		if(properties == null) {
			loadProperties();
		}
		
		properties.setProperty(key, value);
	}
	
	
	private static void loadProperties() {
		synchronized (properties) {
			if(propertiesFileName == null) {
				propertiesFileName = System.getProperty("scu.encrypt.properties.filename");
				
				if(propertiesFileName == null || "".equals(propertiesFileName)) {
					EncryptLogger.error("System property 'scu.encrypt.properties.filename' not found. Loading default properties file '" + DEFAULT_PROPERTIES_FILENAME + "'");
					propertiesFileName = DEFAULT_PROPERTIES_FILENAME;
				}
			}
			
			InputStream inputStream = EncryptProperty.class.getResourceAsStream(propertiesFileName);
			
			inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(propertiesFileName);
			
			properties = new Properties();
			try {
				properties.load(inputStream);
			} catch (IOException e) {
				EncryptLogger.error("Load properties failed..- " + e.getMessage());
				throw new RuntimeException("Load properties failed..- " + e.getMessage());
			}
		}
	}
	
	public static String getPropertiesFileName() {
		return propertiesFileName;
	}

}
