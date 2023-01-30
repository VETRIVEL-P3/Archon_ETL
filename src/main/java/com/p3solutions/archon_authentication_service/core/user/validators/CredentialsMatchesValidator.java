/**
 * 
 */
package com.p3solutions.archon_authentication_service.core.user.validators;

import com.p3solutions.archon_authentication_service.core.user.validators.annotations.CredentialsMatches;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

/**
 * @author saideepak
 *
 */
public class CredentialsMatchesValidator implements ConstraintValidator<CredentialsMatches, Object> {

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.validation.ConstraintValidator#isValid(java.lang.Object,
	 * javax.validation.ConstraintValidatorContext)
	 */
	@Override
	public boolean isValid(Object value, ConstraintValidatorContext context) {
		UserCreateDTO userCreateDTO = (UserCreateDTO) value;
		return userCreateDTO.getPassword().equals(userCreateDTO.getConfirmPassword());
	}

}
