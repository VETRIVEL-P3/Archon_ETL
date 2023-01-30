package com.p3solutions.archon_authentication_service.core.authentication;

import com.p3solutions.archon_authentication_service.core.audit.AuditHelper;
import com.p3solutions.archon_authentication_service.core.authentication.enums.AuthType;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.LoginRequest;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor.TokenExtractor;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.service.SamlUserService;
import com.p3solutions.archon_authentication_service.core.authentication.services.AuthenticationService;
import com.p3solutions.archon_authentication_service.core.user.services.UserService;
import com.p3solutions.archon_authentication_service.core.user.validators.FieldValidator;
import com.p3solutions.archon_authentication_service.core.user.validators.UserCreationValidator;
import com.p3solutions.common_beans_dto.audit.enums.Event;
import com.p3solutions.common_beans_dto.common_beans.ApiFailureMessages;
import com.p3solutions.common_beans_dto.configservice_connector.dto.request.TokenRequestDTO;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.dto.request.PasswordResetDTO;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.beans.SamlUserRequestDTO;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.common_beans_dto.users.dto.response.ResetPasswordResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.TokenResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.UserModelResponseDTO;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.MapBuilder;
import com.p3solutions.utility.common_exceptions.BadRequestException;
import com.p3solutions.utility.common_exceptions.ExceptionHandler;
import com.p3solutions.utility.common_exceptions.LicenseExpiredException;
import com.p3solutions.utility.internationalization.Translator;
import com.p3solutions.utility.jwt.TokenUtils;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang.StringUtils;
import org.json.JSONException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.env.Environment;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.validation.Valid;
import java.io.IOException;
import java.util.Map;
import java.util.Optional;

/**
 * The Rest Controller class for Authentication APIs
 *
 * @author saideepak TODO: need to revisit saml , ldap, licence and audit
 * implementations
 */
@RestController
@RequestMapping("/authentication-management")
@Slf4j
public class AuthenticationController {

    @Autowired
    private UserService userService;
    @Autowired
    private Environment environment;
    @Autowired
    private FieldValidator fieldValidator;
    @Autowired
    private TokenExtractor tokenExtractor;

    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private AuditHelper auditHelper;

    @Value("${saml.enabled}")
    private Boolean samlEnabled;

    @Value("${saml.idp.logout-url}")
    private String samlLogoutUrl;

    @Value(value = "${archon.version}")
    private String archonBuildVersion;

    @Value("${saml.client.redirect-url}")
    private String uiRedirectUrl;

    @Value("${server.ssl.enabled:false}")
    private Boolean sslEnabled;

    @Autowired
    private SamlUserService samlUserService;

    @Autowired
    private UserAbstractRepository userAbstractRepository;
    @Autowired
    private TokenUtils tokenUtils;

    @Value("${jwt.token.signing-key}")
    private String signing_key;

    @Value("${commonAuth.enabled}")
    private Boolean commonAuthentionEnabled;

    /**
     * Sign up user from the request body
     *
     * @return
     * @throws LicenseExpiredException
     * @see UserCreationValidator request body validator
     * @see UserCreateDTO request body form
     */
    @PostMapping("/sign-up")
    public Map<String, UserModelResponseDTO> createUser(@RequestBody UserCreateDTO dto)
            throws BadRequestException {
        fieldValidator.signupValidator(dto);
        UserModelResponseDTO userModelResponseDTO = userService.createUser(dto);
        return MapBuilder.of("userModel",userModelResponseDTO);
    }

    @PostMapping("/sign-in")
    public Map<String, Map<String, String>> loginUser(@RequestBody LoginRequest loginRequest, HttpServletResponse response, HttpServletRequest httpServletRequest)
            throws BadRequestException, LicenseExpiredException {
        auditHelper.LogEvents(loginRequest.getUserId(), Event.SIGN_IN,
                Translator.toLocale("audit.client.host",new String[]{
                        (StringUtils.isNotBlank(httpServletRequest.getHeader("X-FORWARDED-FOR"))? httpServletRequest.getHeader("X-FORWARDED-FOR")
                                : httpServletRequest.getRemoteAddr()), loginRequest.getUserId()})
                , false);
        Map<String, String> tokenMap = userService.loginUser(loginRequest);
        userService.generateCookie(response, tokenMap);
        return  MapBuilder.of("tokenMap",tokenMap);
    }

    /**
     * Get Refresh token
     *
     * @param request
     * @param response
     * @return
     */
    @GetMapping(value = "/token", produces = {MediaType.APPLICATION_JSON_VALUE})
    public @ResponseBody
    Map<String, TokenResponseDTO> refreshToken(HttpServletRequest request, HttpServletResponse response) {

        TokenResponseDTO tokenResponseDTO = userService.generateTokens(request, response);
        return MapBuilder.of("tokenMap",tokenResponseDTO);
    }

    /**
     * Error End point URL
     *
     * @return
     * @throws BadRequestException
     */
    @GetMapping("/error")
    public Map<String, String> errorEndpoint() throws BadRequestException {

        return MapBuilder.of("message", ApiFailureMessages.TECHNICAL_ERROR);
    }

    @GetMapping("/sso/login/url")
    public Map<String, String> ssoLoginUrl() {

        return MapBuilder.of("message", environment.getProperty("saml.login.client.url"));

    }

    @PostMapping("/logout")
    public Map<String, String> logOutUser(@RequestParam(value = "token", required = false) String token,
                                          HttpServletRequest request)
            throws BadRequestException, JSONException {
        if (StringUtils.isEmpty(token))
            token = tokenExtractor.extract(request);
        userService.logout(token);
        return MapBuilder.of("message", Translator.toLocale("authentication.logout"));
    }

    /**
     * This api is to deleiver the saml logout url to the FE. Instead of setting the logout url in the metadata
     * Archon provides a way to configure thru application.yml
     *
     * @return
     */
    @GetMapping("/sso/logout/url")
    public Map<String, String> ssoLogoutUrl() {
        if (samlEnabled)
            return MapBuilder.of("samlLogoutUrl", samlLogoutUrl);
        else
            return MapBuilder.of("samlLogoutUrl", StringUtils.EMPTY);
    }

    /**
     * Sends Reset Password Link to registed email address.
     * <p>
     * <p>
     * Note that currently reset link is being sent to simulate the same experience
     * for development only. Actual email will be sent once email configuration is
     * done.
     *
     * @throws BadRequestException
     * @throws IOException
     */
    @PostMapping("/password-link")
    public Map<String, String> sendForgotPasswordLink(@Valid @RequestBody ForgotPasswordRequestBody requestBody)
            throws BadRequestException, IOException {

        userService.generateForgetPasswordLink(requestBody.getEmailAddress());
        return MapBuilder.of("message", Translator.toLocale("authentication.resetLinkSend"));
    }

    @PostMapping("/reset-password")
    public Map<String, String> updateResetPassword(@RequestBody PasswordResetDTO dto)
            throws BadRequestException {
        userService.generateResetPassword(dto);
        return MapBuilder.of("message", Translator.toLocale("authentication.passwordReset"));
    }

    @GetMapping("/key-value")
    public Map<String,ResetPasswordResponseDTO> getRestKeyDetails(@RequestParam String resetKey)
            throws BadRequestException {
        ResetPasswordResponseDTO resetPasswordResponseDTO = userService.generateResetKey(resetKey);
        return MapBuilder.of("resetPassword",resetPasswordResponseDTO);

    }

    @Data
    private static class ForgotPasswordRequestBody {
        private String emailAddress;
    }

    /**
     * to generate a JWT token which is compatible for the archon-configuration-service
     *
     * @param tokenRequest
     * @return
     * @throws BadRequestException
     * @throws LicenseExpiredException
     */
    @PostMapping("/config/access-token")
    public Map<String, String> getAccessToken(@RequestBody TokenRequestDTO tokenRequest)
            throws BadRequestException, LicenseExpiredException {
        String tokenForConfig = userService.getAccessToken(tokenRequest.getUserId(), tokenRequest.getPassword());
        return  MapBuilder.of("token",tokenForConfig);
    }

    /**
     * Api to get the active authentication
     *
     * @return
     */
    @GetMapping("/auth-type")
    public Map<String, AuthType> getAuthType(){
        AuthType activeAuth = authenticationService.getActiveAuth();
        return  MapBuilder.of("activeAuthentication", activeAuth);
    }

    /**
     * Api to get the active authentication
     *
     * @return
     */
    @GetMapping("/build-version")
    public Map<String, String> archonBuildVersion(){
        return  MapBuilder.of("archonBuildVersion", archonBuildVersion);
    }

    /**
     * Api to get the token from the cookie
     * @return
     */
    @GetMapping("/current-token")
    public Map<String, String> getTokenFromCookie(HttpServletRequest request){
        String token = tokenExtractor.extract(request);
        if (commonAuthentionEnabled) {
            try {
                String userName = tokenUtils.getUserID(token);
                return  MapBuilder.of("currentToken", token);
            }catch (Exception exception) {
                String encryptedUserName = getCommonAuthUserID(token);
                try {
                    Optional<UserModelMapperBean> userModel = userAbstractRepository.findByIdAndType(encryptedUserName, "SAML_SSO");
                    UserModelMapperBean userBean = null;
                    if (userModel.isPresent()) {
                        userBean = userModel.get();
                        String samlParseToken = samlUserService.generateToken(userBean, "accessToken");
                        return MapBuilder.of("currentToken", samlParseToken);
                    }
                } catch (Exception e) {
                    // Switching Module problem
                }
            }
        }else{
            return  MapBuilder.of("currentToken", token);
        }
        return MapBuilder.of("currentToken",  StringUtils.EMPTY);
    }


    @GetMapping("/saml-parse-token")
    public void parseSamlToken(HttpServletRequest request, HttpServletResponse response) throws IOException {
        String tokenInformation = tokenExtractor.extract(request);
        try {
            String encryptedUserName = getCommonAuthUserID(tokenInformation);
            try {
                Optional<UserModelMapperBean> userModel = userAbstractRepository.findByIdAndType(encryptedUserName, "SAML_SSO");
                UserModelMapperBean userBean = null;
                if (userModel.isPresent()) {
                    userBean = userModel.get();
                    String token = samlUserService.generateToken(userBean, "accessToken");
                    String refreshToken = samlUserService.generateToken(userBean, "refreshToken");
                    response.addCookie(createCookie("accessToken", token));
                    response.addCookie(createCookie("refreshToken", refreshToken));
                } else {
                    throw new BadRequestException("Invalid user Id ");
                }
            }catch (Exception e) {
                response.addCookie(createCookie("accessToken", StringUtils.EMPTY));
                response.addCookie(createCookie("refreshToken", StringUtils.EMPTY));
            }
        }catch (Exception exception){
            // return  MapBuilder.of("currentToken", tokenInformation);
            // Taken Existing token while switching
        }
    }

    /**
     * Api to get the token from the cookie
     *
     * @return
     */
    @PostMapping("/saml-user")
    public boolean getTokenFromCookie(@RequestBody SamlUserRequestDTO samlUserRequestDTO, HttpServletRequest request) {
        UserModelMapperBean userBean = null;
        String tokenInformation = tokenExtractor.extract(request);
        String userName = getCommonAuthUserID(tokenInformation);
        boolean isCreated=false;
        try {
            if(userName.equalsIgnoreCase(samlUserRequestDTO.getUserName())) {
                Optional<UserModelMapperBean> userModel = userAbstractRepository.findByIdAndType(samlUserRequestDTO.getUserName(), "SAML_SSO");
                if (userModel.isPresent()) {
                    userBean = samlUserService.updateUserRoles(samlUserRequestDTO, userModel.get());
                    try {
                        auditHelper.LogEvents(userModel.get().getId(), Event.SIGN_IN, Translator.toLocale("audit.signIn.saml",
                                new String[]{userModel.get().getEmailAddress(), userModel.get().getId()}), false);
                    } catch (Exception e) {
                        log.error(e.getMessage());
                    }
                } else {
                    userBean = samlUserService.createSAMLUserEntry(samlUserRequestDTO);
                }
                isCreated= true;
            }
        } catch (Exception e) {
           ExceptionHandler.exception(e.getMessage(),e);
        }
        return isCreated;
    }

    private Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setPath("/");
        if (sslEnabled)
            cookie.setSecure(true);
        cookie.setHttpOnly(true);
        return cookie;
    }


    public String getCommonAuthUserID(String jwtTokenBearer) {
        String jwt = jwtTokenBearer;
        if (jwtTokenBearer.startsWith("Bearer "))
            jwt = jwtTokenBearer.split(" ")[1];
        return Jwts.parser()
                .setSigningKey(signing_key.getBytes())
                .parseClaimsJws(jwt).getBody().get("sub").toString();
    }
}
