package com.p3solutions.archon_authentication_service.core.user.services;

import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.LoginRequest;
import com.p3solutions.common_beans_dto.global_groups_roles.dto.response.GlobalGroupResponseDTO;
import com.p3solutions.common_beans_dto.global_groups_roles.dto.response.GlobalRoleResponseDTO;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalGroupMapperBean;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalRoleMapperBean;
import com.p3solutions.common_beans_dto.users.dto.request.PasswordResetDTO;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.common_beans_dto.users.dto.response.ResetPasswordResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.TokenResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.UserModelResponseDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.common_exceptions.BadRequestException;
import com.p3solutions.utility.common_exceptions.LicenseExpiredException;
import org.json.JSONException;
import org.springframework.context.NoSuchMessageException;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Service for logical operations on {@link UserModelResponseDTO} and related
 * functionalities.
 *
 * @author vishwabhat
 */
public interface UserService {

	/**
	 * Finds user model by given email address parameter
	 *
	 * @param emailAddress is the email address of the user
	 * @return Optional user model. If no model present, returns Optional#empty()
	 */
	Optional<UserModelMapperBean> findByEmailAddress(String emailAddress);

	/**
	 * Finds user model by given user ID
	 *
	 * @param userId Stringified {@link org.bson.types.ObjectId} represetation of
	 *               User ID
	 * @return Returns {@link Optional} of {@link UserModelResponseDTO}. If no user found then
	 *         returns {@link Optional#empty()}
	 */
	Optional<UserModelMapperBean> findById(final String userId);

	/**
	 * To get the current user..
	 * 
	 * @author syed sirajuddin
	 * @return
	 */
	public UserModelMapperBean currentUser() throws BadRequestException;

	/**
	 * Create user ...
	 */
	public UserModelResponseDTO createUser(UserCreateDTO dto) throws  BadRequestException;

	/**
	 * create user entry for SAML
	 *
	 */
	public UserModelMapperBean createSAMLUser(UserCreateDTO dto, List<String> groupNames) throws  BadRequestException;

	/**
	 * To update the saml user
	 * Updating the groups assigned to the user
	 */
	UserModelMapperBean updateSAMLUser(UserModelMapperBean userBean, List<String> groupNames) throws BadRequestException;

	/**
	 * Login User
	 */

	public Map<String, String> loginUser(LoginRequest loginRequest)
			throws NoSuchMessageException, BadRequestException, LicenseExpiredException;

	/**
	 * Token genration
	 */

	public TokenResponseDTO generateTokens(HttpServletRequest request, HttpServletResponse response);

	public void generateForgetPasswordLink(String emailAddress)throws BadRequestException, IOException ;
	
	public ResetPasswordResponseDTO generateResetKey(String resetKey)throws BadRequestException;
	
	public void generateResetPassword(PasswordResetDTO dto)throws BadRequestException;
	
	public void logout(String token)throws BadRequestException, JSONException;

	/**
	 * To get the Group details of a group..
	 * 
	 * @param groupId
	 */
	public GlobalGroupMapperBean getGlobalGroupDetail(String groupId);

	// this method is used to change the global group of a user after checking the
	// dependency on dataSource and workspace
	public List<GlobalRoleMapperBean> getRolesInGroup(List<GlobalGroupMapperBean> groupList);
	/**
	 * To check user is valid or not
	 * 
	 * @param :userId
	 * @return : boolean expersion
	 * 
	 * @author chetana
	 */

	public boolean checkUserValid(String userId) throws BadRequestException;

	public void validationForResetPasswordDTO(PasswordResetDTO dto) throws BadRequestException;

	public Boolean updateResetPasswordForUser(PasswordResetDTO dto) throws BadRequestException;

	public boolean checkTokenExpired(long createdAtDate);
	public Optional<String> getCurrentUserId();

	public boolean isValidEmailAddress(String email);

	/**
	 * To get the accesstoken to connect to the config service apis
	 * @param username
	 * @param encodedPassword
	 * @return
	 */
	String getAccessToken(String username, String encodedPassword);

	/**
	 * to generate cookie and attach the cookie in the response object
	 * @param response
	 * @param tokens
	 */
	void generateCookie(HttpServletResponse response, Map<String, String> tokens);

}
