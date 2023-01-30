package com.p3solutions.archon_authentication_service.core.user.validators;

import com.p3solutions.common_beans_dto.common_constants.ApiErrorCodeMessages;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.Validators;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;
import org.springframework.validation.Errors;
import org.springframework.validation.ValidationUtils;
import org.springframework.validation.Validator;

import java.util.Optional;

/**
 * Validation Class for {@link UserCreateDTO}
 *
 * @author vishwabhat
 */
@Component("userCreationValidator")
public class UserCreationValidator implements Validator {

  @Autowired
  private UserAbstractRepository userAbstractRepository;

  private Logger log = LoggerFactory.getLogger(getClass());

  @Override
  public boolean supports(Class<?> clazz) {
    log.trace("Class support check: {} == {}", UserCreateDTO.class, clazz);
    return UserCreateDTO.class.isAssignableFrom(clazz);
  }

  @Override
  public void validate(Object target, Errors errors) {
    log.trace("User creation validation on target: {}", target);
    
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, UserCreateDTO.Fields.firstName.name(), "firstName.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, UserCreateDTO.Fields.lastName.name(), "lastName.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, UserCreateDTO.Fields.emailAddress.name(), "emailAddress.required");
    ValidationUtils.rejectIfEmptyOrWhitespace(errors, UserCreateDTO.Fields.password.name(), "credentials.required");

    if (!errors.hasErrors()) {
      UserCreateDTO model = (UserCreateDTO) target;
      final String email = model.getEmailAddress();

      if(model.getPassword().length() < 6) {
        log.trace("password length is less than 6");
        errors.rejectValue(UserCreateDTO.Fields.password.name(), ApiErrorCodeMessages.SCRT_INVALID_LENGTH);
      }

      if (!Validators.email(email.toLowerCase())) {
        log.trace("email invalid format");
        errors.rejectValue(
            UserCreateDTO.Fields.emailAddress.name(),
            ApiErrorCodeMessages.EMAILADDRESS_INVALID_FORMAT);
      }

      final Optional<UserModelMapperBean> existingUserWithNewEmailAddress =
              userAbstractRepository
              .findByEmailAddressIgnoreCase(model.getEmailAddress().toLowerCase());
      if (existingUserWithNewEmailAddress.isPresent()) {
        log.trace("profile already exists for given email address");
        errors.rejectValue(UserCreateDTO.Fields.emailAddress.name(), ApiErrorCodeMessages.PROFILE_EXISTS);
      }
    }

    log.trace("Validation Errors: {}", errors.getAllErrors());
  }
}
