package com.p3solutions.archon_authentication_service.core.user.utility;

import com.p3solutions.common_beans_dto.common_constants.ApiErrorCodeMessages;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.dto.response.UserModelResponseDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import org.apache.commons.lang.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.util.Optional;

@Component
public class UserManageDtoValidator {

	@Autowired
	UserAbstractRepository userAbstractRepository;

	public String userManageDtoValidator(String emailAddress) {
		String isValid = StringUtils.EMPTY;
		if (emailAddress != null) {
			Optional<UserModelMapperBean> userInfo = userAbstractRepository.findByEmailAddressIgnoreCase(emailAddress);

			if (!userInfo.isPresent()) {
				return ApiErrorCodeMessages.EMAILADDRESS_INVALID_FORMAT;
			}
		}
		return isValid;

	}

}
