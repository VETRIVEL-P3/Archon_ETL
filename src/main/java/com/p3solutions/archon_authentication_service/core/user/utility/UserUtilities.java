package com.p3solutions.archon_authentication_service.core.user.utility;

import java.util.Random;

public class UserUtilities {
	
	private static Random randomGenerator = new Random();

	public static String generateRandomPassword(int len) {

		// A strong password has Cap_chars, Lower_chars,
		// numeric value and symbols. So we are using all of
		// them to generate our password
		String capitalChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
		String smallChars = "abcdefghijklmnopqrstuvwxyz";
		String numbers = "0123456789";
		String symbols = "!@#$%^&*_=+-/.?<>)";

		String values = capitalChars + smallChars + numbers + symbols;

		// Using random method
		

		char[] password = new char[len];

		for (int i = 0; i < len; i++) {
			// Use of charAt() method : to get character value
			// Use of nextInt() as it is scanning the value as int
			password[i] = values.charAt(randomGenerator.nextInt(values.length()));

		}
		return password.toString();

	}

}
