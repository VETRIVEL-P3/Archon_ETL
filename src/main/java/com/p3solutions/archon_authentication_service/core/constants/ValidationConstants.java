/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.constants;

/**
 * @author saideepak
 *
 */
public final class ValidationConstants {

	private ValidationConstants() {
	}

	public static final String NO_USER_ID = "User ID is not Given";
	public static final String NO_EMAIL_ID = "Email ID is not Given";
	public static final String NO_FIRST_NAME = "First Name is not Given";
	public static final String NO_LAST_NAME = "Last Name is not Given";
	public static final String NO_CREDENTIALS = "Credentials are not provided";
	public static final String NO_CONFIRM_CREDENTIALS = "Credential Confirmation is not Given";

	public static final String INVALID_EMAIL = "Invalid EMAIl ID";
	public static final String CREDENTIALS_DONT_MATCH = "The credentials you have provided do not match";
	public static final String EMAIL_EXISTS = "Email ID alreadys exists";
	public static final String INVALID_ROLE = "The chosen role is invalid";
	public static final String INVALID_CREDENTIALS = "The given credentials are weak.It should be of atleast 8 digits including atleast one lowercase alphabet, one uppercase alphabet,one numeric and one symbol.";

}
