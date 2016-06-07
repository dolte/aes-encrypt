package com.dolte.encrypt;

public class EncryptLogger {
	public static final int DEBUG = 1;
	public static final int INFO = 2;
	public static final int ERROR = 3;
	
	
	private static int loggerLevel;
	private static boolean loadedLevel = false;
	
	static {
		loggerLevel = DEBUG;
	}

	private static void loadLevel() {
		String levelName = EncryptProperty.getProperty(EncryptProperty.PROP_LOGGER_LEVEL);
		if(levelName != null && !"".equals(levelName)) {
			if(levelName.equalsIgnoreCase("INFO")) {
				loggerLevel = INFO;
			} else if (levelName.equalsIgnoreCase("ERROR")) {
				loggerLevel = ERROR;
			}
		}
		loadedLevel = true;
	}
	
	public static void debug(String msg) {
		if(!loadedLevel) {
			loadLevel();
		}
		if(loggerLevel <= DEBUG) {
			System.out.println("[SCU_ENC][DEBUG] " + msg);
		}
	}

	public static void info(String msg) {
		if(!loadedLevel) {
			loadLevel();
		}
		if(loggerLevel <= INFO) {
			System.out.println("[SCU_ENC][INFO ] " + msg);
		}
	}
	
	public static void error(String msg) {
		System.out.println("[SCU_ENC][ERROR] " + msg);
	}
	
	public static void error(String msg, Throwable throwable) {
		System.out.println("[SCU_ENC][ERROR] " + msg + " - " + throwable.getMessage());
	}
}
