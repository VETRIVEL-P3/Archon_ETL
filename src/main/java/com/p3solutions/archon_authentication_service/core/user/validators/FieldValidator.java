package com.p3solutions.archon_authentication_service.core.user.validators;

import com.p3solutions.common_beans_dto.users.abstract_repository.InviteUserAbstractRepository;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.utility.common_exceptions.BadRequestException;
import com.p3solutions.utility.internationalization.Translator;
import org.apache.commons.codec.binary.Base64;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class FieldValidator {
    private static final String EMAIL_PATTERN = "^[-a-z0-9~!$%^&*_=+}{\'?]+(\\.[-a-z0-9~!$%^&*_=+}{\'?]+)*@([a-z0-9_][-a-z0-9_]*(\\.[-a-z0-9_]+)*\\.(aero|arpa|biz|com|coop|edu|gov|info|int|mil|museum|name|net|org|pro|travel|mobi|[a-z][a-z])|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,5})?$";
    private static final String SCRT_PATTERN = "^(?=.*[0-9])(?=.*[a-z])(?=.*[A-Z])(?=.*[@#$%^&+=])(?=\\S+$).{8,20}$";

    @Autowired
    private UserAbstractRepository userAbstractRepository;
    @Autowired
    private InviteUserAbstractRepository inviteUserAbstractRepository;
//	@Autowired
//	private MessageSource messageSource;

    public void signupValidator(UserCreateDTO dto) throws BadRequestException {
        if (!validateEmail(dto.getEmailAddress().toLowerCase())) {
            throw new BadRequestException(Translator.toLocale("email.invalid"));
        }
        if (userAbstractRepository.findByEmailAddressIgnoreCase(dto.getEmailAddress()).isPresent()) {
            throw new BadRequestException(Translator.toLocale("email.exists"));
        }
        if (!inviteUserAbstractRepository.findByEmailAddress(dto.getEmailAddress()).isPresent()) {
            throw new BadRequestException(Translator.toLocale("email.notexists"));
        }
        byte[] byteArray = Base64.decodeBase64(dto.getPassword());
        String decodedPassword = new String(byteArray);
        Pattern pattern = Pattern.compile(SCRT_PATTERN);
        Matcher matcher = pattern.matcher(decodedPassword);
        if (!matcher.matches()) {
            throw new BadRequestException(Translator.toLocale("password.exists"));
        }
        if (!dto.getPassword().equals(dto.getConfirmPassword())) {
            throw new BadRequestException(Translator.toLocale("password.matches"));
        }
    }

    private boolean validateEmail(String email) {
        Pattern pattern = Pattern.compile(EMAIL_PATTERN);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }
}
