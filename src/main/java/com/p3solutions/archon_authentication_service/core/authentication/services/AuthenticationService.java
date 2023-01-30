package com.p3solutions.archon_authentication_service.core.authentication.services;

import com.p3solutions.archon_authentication_service.core.authentication.enums.AuthType;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalGroupMapperBean;
import com.p3solutions.common_beans_dto.users.dto.response.UserModelResponseDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.common_exceptions.BadRequestException;

import java.util.List;

public interface AuthenticationService {

	public UserModelMapperBean signUpUser(UserModelMapperBean usermodel) throws BadRequestException;

	public UserModelMapperBean signUpSAMLUser(UserModelMapperBean usermodel, List<GlobalGroupMapperBean> groups) throws BadRequestException;
	
	public void userIdFirstCharValidation(String userId) throws BadRequestException;
	
	public void userIdMaxCharValidation(String userId) throws BadRequestException;

	AuthType getActiveAuth();

}
