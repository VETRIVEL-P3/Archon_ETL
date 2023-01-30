package com.p3solutions.archon_authentication_service.core.user.validators;

import com.p3solutions.archon_authentication_service.core.user.validators.annotations.EmailExists;
import com.p3solutions.common_beans_dto.users.abstract_repository.InviteUserAbstractRepository;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;



/**
 * Validates if the Email is present in Database
 * 
 * @author saideepak
 *
 */
public class EmailExistsValidator implements ConstraintValidator<EmailExists, String> {

	@Autowired
	private InviteUserAbstractRepository inviteUserAbstractRepository;
	

	/*
	 * (non-Javadoc)
	 * 
	 * @see javax.validation.ConstraintValidator#isValid(java.lang.Object,
	 * javax.validation.ConstraintValidatorContext)
	 */
	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {

		return emailExists(value);
	}

	private boolean emailExists(String emailAddress) {
		return inviteUserAbstractRepository.findByEmailAddress(emailAddress).isPresent();
	}

}
