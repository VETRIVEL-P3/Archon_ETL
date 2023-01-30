package com.p3solutions.archon_authentication_service.core.user.validators;

import com.p3solutions.archon_authentication_service.core.user.validators.annotations.UserExists;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import org.springframework.beans.factory.annotation.Autowired;

import javax.validation.ConstraintValidator;
import javax.validation.ConstraintValidatorContext;

public class UserValidator implements ConstraintValidator<UserExists, String> {

	@Autowired
	private UserAbstractRepository userAbstractRepository;

	@Override
	public boolean isValid(String value, ConstraintValidatorContext context) {
		return (!userAbstractRepository.findByEmailAddressIgnoreCase(value).isPresent());
	}

}
