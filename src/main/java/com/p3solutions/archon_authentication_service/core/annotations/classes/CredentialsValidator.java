package com.p3solutions.archon_authentication_service.core.annotations.classes;

import com.p3solutions.archon_authentication_service.core.annotations.ValidCredentials;
import org.apache.commons.codec.binary.Base64;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CredentialsValidator implements ConstraintValidator<ValidCredentials, String> {

	private static final String SCRT_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";

	public static boolean CredentialValidation(String credentials) {
		Pattern pattern = Pattern.compile(SCRT_PATTERN);
		Matcher matcher = pattern.matcher(credentials);
		return matcher.matches();
	}

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		
		byte[] byteArray = Base64.decodeBase64(value);
		String decodedCredentials = new String(byteArray);
		return CredentialValidation(decodedCredentials);
	}

}
