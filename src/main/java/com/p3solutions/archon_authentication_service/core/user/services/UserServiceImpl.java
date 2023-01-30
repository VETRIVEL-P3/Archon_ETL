package com.p3solutions.archon_authentication_service.core.user.services;

import com.fasterxml.jackson.core.JsonParseException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.archon_authentication_service.core.audit.AuditHelper;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.AjaxAuthenticationProvider;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.LoginRequest;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenGenerator;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtAccessToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtRefreshToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.exceptions.InvalidJwtTokenException;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor.TokenExtractor;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.verifier.TokenVerifier;
import com.p3solutions.archon_authentication_service.core.authentication.services.AuthenticationService;
import com.p3solutions.archon_authentication_service.core.constants.JwtConstants;
import com.p3solutions.archon_authentication_service.core.feign.SMTPFeignClient;
import com.p3solutions.archon_authentication_service.core.feign.SMTPFeignClientHTTP;
import com.p3solutions.archon_authentication_service.core.license_management.LicenseCheckerService;
import com.p3solutions.common_beans_dto.audit.enums.Event;
import com.p3solutions.common_beans_dto.authentication.abstract_repository.TokenAbstractRespository;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.authentication.beans.TokenExpiryDetails;
import com.p3solutions.common_beans_dto.common_beans.MailNotificationModel;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.common_beans_dto.common_constants.MailConstants;
import com.p3solutions.common_beans_dto.global_groups_roles.abstract_repository.GlobalGroupAbstractRepository;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalGroupMapperBean;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalRoleMapperBean;
import com.p3solutions.common_beans_dto.notification.dto.responsedto.SMTPResponseDTO;
import com.p3solutions.common_beans_dto.users.abstract_repository.InviteUserAbstractRepository;
import com.p3solutions.common_beans_dto.users.abstract_repository.ResetPasswordAbstractRepository;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.dto.request.PasswordResetDTO;
import com.p3solutions.common_beans_dto.users.dto.request.ResetPasswordRequestDTO;
import com.p3solutions.common_beans_dto.users.dto.request.UserCreateDTO;
import com.p3solutions.common_beans_dto.users.dto.response.ResetPasswordResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.TokenResponseDTO;
import com.p3solutions.common_beans_dto.users.dto.response.UserModelResponseDTO;
import com.p3solutions.common_beans_dto.users.enums.EmailType;
import com.p3solutions.common_beans_dto.users.mapper_beans.ResetPasswordMapperBean;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.kafka.messengers.Messenger;
import com.p3solutions.utility.Validators;
import com.p3solutions.utility.common_exceptions.*;
import com.p3solutions.utility.encryption.user_account.EncryptionUtil;
import com.p3solutions.utility.internationalization.Translator;
import com.p3solutions.utility.mapper.MapperUtils;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.codec.binary.Base64;
import org.json.JSONException;
import org.owasp.encoder.Encode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.NoSuchMessageException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import static com.p3solutions.common_beans_dto.common_constants.FailureMessages.*;
import static com.p3solutions.utility.Exceptions.checkArgument;
import static com.p3solutions.utility.common_exceptions.ServerException.throwIfTrue;
import static org.springframework.util.StringUtils.containsWhitespace;
import static org.springframework.util.StringUtils.isEmpty;

@Service
@Slf4j
public class UserServiceImpl implements UserService {

    private static final String EMAIL_ADDRESS_PARAM = "Email Address";
    private static final String USER_ID_PARAM = "User Id";
    private static final String USER_NAME_PARAM = "User Name";
    private static final String PASSWORD_PARAM = "password";
    private static final String RESET_KEY_PARAM = "resetKey";
    @org.springframework.beans.factory.annotation.Value("${enableldapauth}")
    private Boolean enableLdapLogin;
    @Autowired
    private AjaxAuthenticationProvider authenticationManager;
    @Autowired
    private JwtTokenGenerator tokenFactory;
    @Autowired
    private TokenVerifier tokenVerifier;
    @Autowired
    private TokenExtractor tokenExtractor;
    @Value("${jwt.token.signing-key}")
    public String tokenSigningKey;
    @Value(value = "${eureka.client.serviceUrl.defaultZone}")
    private String url;
    @Value(value = "${resetPasswordUrl.url}")
    private String resetPasswordUrl;
    @Value(value = "${kafka.topic.name.send-email}")
    private String sendEmailTopic;
    @Autowired
    private SMTPFeignClient smtpFeignClient;
    @Autowired
    private SMTPFeignClientHTTP smtpFeignClientHTTP;
    @Autowired
    private Messenger messenger;

    @Autowired
    private TokenAbstractRespository tokenModelAbstractRepository;
    @Autowired
    private AuthenticationService authenticationService;
    @Autowired
    private GlobalGroupAbstractRepository globalGroupAbstractRepository;
    @Autowired
    private MapperUtils mapperUtils;
    @Autowired
    private AuditHelper auditHelper;
    @Autowired
    UserAbstractRepository userAbstractRepository;
    @Autowired
    InviteUserAbstractRepository inviteUserAbstractRepository;
    @Autowired
    ResetPasswordAbstractRepository resetPasswordAbstractRepository;
    @Autowired
    LicenseCheckerService licenseCheckerService;

    private String EVENT_DETAILS;

    @Value(value = "${server.ssl.enabled}")
    private Boolean sslEnabled;

   // private static final Logger LOGGER = Loggers.getLogger("UserServiceImpl");
    @Override
    public Optional<UserModelMapperBean> findByEmailAddress(String emailAddress) {
        checkArgument(!isEmpty(emailAddress), "Please enter a valid email address.");
        checkArgument(Validators.email(emailAddress), "Please enter a valid email address.");
        return userAbstractRepository.findByEmailAddressIgnoreCase(emailAddress.toLowerCase());
    }

    @Override
    public Optional<UserModelMapperBean> findById(final String userId) {
        throwIfTrue(StringUtils.isEmpty(userId), MISSING_METHOD_PARAMETER.apply(USER_ID_PARAM));
        // throwIfFalse(ObjectId.isValid(userId), FailureMessages.INVALID_ID_FORMAT);
        return userAbstractRepository.findById(userId);
    }

    @Override
    public UserModelMapperBean currentUser() throws BadRequestException {
        String userId = getCurrentUserId().get();
        final UserModelMapperBean userModelResponseDTO = userAbstractRepository.findById(userId)
                .orElseThrow(() -> new BadRequestException(FailureMessages.INVALID_USER_ID));
        return userModelResponseDTO;
    }

    @Override
    public GlobalGroupMapperBean getGlobalGroupDetail(String groupId) {
        GlobalGroupMapperBean globalGroupInfo = null;
        try {
            globalGroupInfo = globalGroupAbstractRepository.findByID(groupId).orElseThrow(() -> new InvalidInput("Invalid Input"));
        } catch (Exception e) {
            ExceptionHandler.exception("Failed to get global group details", e);
        }
        return globalGroupInfo;

    }

    @Override
    public Optional<String> getCurrentUserId() {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public List<GlobalRoleMapperBean> getRolesInGroup(List<GlobalGroupMapperBean> groupList) {
        List<GlobalRoleMapperBean> roleList = new ArrayList<GlobalRoleMapperBean>();
        if (!CollectionUtils.isEmpty(groupList)) {
            for (GlobalGroupMapperBean group : groupList) {
                roleList.addAll(group.getGlobalRoles());
            }
        }
        HashSet<GlobalRoleMapperBean> set = new HashSet<GlobalRoleMapperBean>(roleList);
        roleList.clear();
        roleList.addAll(set);
        return roleList;
    }

    @Override
    public void validationForResetPasswordDTO(PasswordResetDTO dto) throws BadRequestException {
        if (org.apache.commons.lang.StringUtils.isBlank(dto.getEmailAddress())) {
            throw new BadRequestException(FailureMessages.EMAIL_ADDRESS_REQUIRED);
        }
        if (org.apache.commons.lang.StringUtils.isBlank(dto.getPassword())) {
            throw new BadRequestException(FailureMessages.PASSWORD_REQUIRED);
        }
        if (org.apache.commons.lang.StringUtils.isBlank(dto.getConfirmPassword())) {
            throw new BadRequestException(FailureMessages.CONFIRM_PASSWORD_REQUIRED);
        }

    }

    @Override
    public Boolean updateResetPasswordForUser(PasswordResetDTO dto) throws BadRequestException {
        boolean checkPassword = false;
        try {
            UserModelMapperBean userModelResponseDTO = userAbstractRepository.findByEmailAddressIgnoreCase(dto.getEmailAddress()).orElseThrow(() -> new BadRequestException(FailureMessages.INVALID_EMAIL_ADDRESS));
            byte[] byteArray = Base64.decodeBase64(dto.getPassword());
            String decodedPassword = new String(byteArray);
            ArrayList<String> oldPasswordList = userModelResponseDTO.getOldPasswords();
            if (!CollectionUtils.isEmpty(oldPasswordList)) {
                for (String oldPassword : oldPasswordList) {
                    checkPassword = EncryptionUtil.isSame(oldPassword, decodedPassword);
                    if (checkPassword) {
                        throw new BadRequestException("Password should not be same as any of the last 3 old passwords");
                    }
                }
            }
            if (!oldPasswordList.isEmpty() && userModelResponseDTO.getOldPasswords().size() < 3) {
                oldPasswordList.add(EncryptionUtil.encrypt(decodedPassword));
            } else {
                oldPasswordList.set(((userModelResponseDTO.getOldPasswords().size() - 3) + 1), EncryptionUtil.encrypt(decodedPassword));
            }
            userModelResponseDTO.setOldPasswords(oldPasswordList);
            userModelResponseDTO.setPassword(EncryptionUtil.encrypt(decodedPassword));
            userAbstractRepository.save(userModelResponseDTO);
            // after save password , again if click forget password link , it will show
            // invalid
            ResetPasswordRequestDTO restKeyDetails = getResetPasswordRequestDTO(dto.getResetKey());
            restKeyDetails.setIsLinkAccessByUser(true);
            resetPasswordAbstractRepository.save(restKeyDetails);
        } catch (Exception e) {
            ExceptionHandler.exception("Failed to Reset the Password due to Exception", e);
            throw new BadRequestException(e.getMessage());
        }
        return true;

    }

    @Override
    public boolean checkUserValid(String userId) throws BadRequestException {
        try {
            UserModelMapperBean user = userAbstractRepository.findById(userId).orElseThrow(() -> new BadRequestException(FailureMessages.INVALID_USER_ID));
            if (user.isSoftDeleted()) {
                return true;
            }
        } catch (Exception e) {
            ExceptionHandler.exception(e.getMessage(), e);
            throw new BadRequestException(e.getMessage());
        }
        return false;

    }

    @Override
    public boolean checkTokenExpired(long createdAtDate) {
        try {
            Date PerviousDate = new Date(createdAtDate * 1000);
            Calendar calUpdated = Calendar.getInstance();
            calUpdated.setTime(PerviousDate);
            calUpdated.add(Calendar.DAY_OF_WEEK, 1);
            Date currentDate = new Date();
            Calendar calCurrent = Calendar.getInstance();
            calCurrent.setTime(currentDate);
            if (calUpdated.getTime().before(calCurrent.getTime())) {
                return true;
            }
        } catch (Exception ex) {
            ExceptionHandler.exception("Token Expired", ex);
        }
        return false;
    }

    @Override
    public UserModelResponseDTO createUser(UserCreateDTO userCreateDTO) throws BadRequestException {

        ArrayList<String> passwordUpdates = new ArrayList<String>();
        byte[] byteArray = Base64.decodeBase64(userCreateDTO.getPassword());
        String decodedPassword = new String(byteArray);
        userCreateDTO.setPassword(decodedPassword);
        byte[] byteArray1 = Base64.decodeBase64(userCreateDTO.getConfirmPassword());
        String decodedConfirmPassword = new String(byteArray1);
        userCreateDTO.setConfirmPassword(decodedConfirmPassword);

        if(!isValidEmailAddress(userCreateDTO.getEmailAddress())){
            throw new BadRequestException(Translator.toLocale("user.inValidEmail"));
        }
        userCreateDTO.setPassword(decodedPassword);
        UserModelMapperBean userModelResponseDTO = UserModelMapperBean.builder().build();
        userModelResponseDTO.setId(userCreateDTO.getUserId());
        userModelResponseDTO.setFirstName(userCreateDTO.getFirstName());
        userModelResponseDTO.setLastName(userCreateDTO.getLastName());
        userModelResponseDTO.setEmailAddress(userCreateDTO.getEmailAddress().toLowerCase());
        userModelResponseDTO.setPassword(EncryptionUtil.encrypt(userCreateDTO.getPassword()));
        Optional<UserModelMapperBean> model = userAbstractRepository.findByIdIgnoreCase(userModelResponseDTO.getId());
        if (model.isPresent() || userCreateDTO.getUserId().equalsIgnoreCase("system")) {
            throw new ServerException(Translator.toLocale("user.idExists"));
        }
        passwordUpdates.add(userModelResponseDTO.getPassword());

        userModelResponseDTO.setOldPasswords(passwordUpdates);
        userModelResponseDTO.setAccessRevoked(false);
        userModelResponseDTO.setAccountLocked(false);
        userModelResponseDTO.setAttemptCount(0);
        if (userModelResponseDTO.getType().equals("ARCHON_DATABASE")) {
            authenticationService.userIdMaxCharValidation(userModelResponseDTO.getId());
            authenticationService.userIdFirstCharValidation(userModelResponseDTO.getId());
        }
        UserModelMapperBean userBean = authenticationService.signUpUser(userModelResponseDTO);
        UserModelResponseDTO user = mapperUtils.map(userBean, UserModelResponseDTO.class);
        // Audit

        auditHelper.LogEvents(userCreateDTO.getUserId(), Event.SIGN_UP, Translator.toLocale("audit.signUp",
                new String[]{userModelResponseDTO.getEmailAddress(), user.getId()}), false);
        UserModelResponseDTO userResponse = UserModelResponseDTO.builder().firstName(user.getFirstName())
                .lastName(user.getLastName()).emailAddress(user.getEmailAddress()).modifiedBy(user.getModifiedBy())
                .globalGroups(user.getGlobalGroups()).globalRoles(user.getGlobalRoles())
                .businessJustification(user.getBusinessJustification()).accessRevoked(user.getAccessRevoked())
                .lockedDuration(user.getLockedDuration()).accountLocked(user.getAccountLocked())
                .attemptCount(user.getAttemptCount()).type(user.getType()).build();

        return userResponse;
    }

    @Override
    public UserModelMapperBean createSAMLUser(UserCreateDTO userCreateDTO, List<String> groupNames) throws BadRequestException {

        if(!isValidEmailAddress(userCreateDTO.getEmailAddress())){
            //throw new BadRequestException(Translator.toLocale("user.inValidEmail"));
            log.error("Email is not Available in SAML Response, Proceeding without Email ID");
        }
        UserModelMapperBean userModelResponseDTO = UserModelMapperBean.builder().build();
        userModelResponseDTO.setId(userCreateDTO.getUserId());
        userModelResponseDTO.setFirstName(userCreateDTO.getFirstName());
        userModelResponseDTO.setLastName(userCreateDTO.getLastName());
        userModelResponseDTO.setEmailAddress(userCreateDTO.getEmailAddress().toLowerCase());
        Optional<UserModelMapperBean> model = userAbstractRepository.findByIdIgnoreCase(userModelResponseDTO.getId());
        if (model.isPresent() || userCreateDTO.getUserId().equalsIgnoreCase("system")) {
            throw new ServerException(Translator.toLocale("user.idExists"));
        }
        userModelResponseDTO.setType("SAML_SSO");
        userModelResponseDTO.setAccessRevoked(false);
        userModelResponseDTO.setAccountLocked(false);
        userModelResponseDTO.setAttemptCount(0);

        UserModelMapperBean userBean = authenticationService.signUpSAMLUser(userModelResponseDTO, addGroups(groupNames));
        try {
            auditHelper.LogEvents(userCreateDTO.getUserId(), Event.SIGN_UP, Translator.toLocale("audit.signUp.saml",
                    new String[]{userModelResponseDTO.getEmailAddress(), userCreateDTO.getUserId()}), false);
        } catch (Exception e){
            log.error(e.getMessage());
        }

        return userBean;
    }

    @Override
    public UserModelMapperBean updateSAMLUser(UserModelMapperBean userBean, List<String> groupNames) throws BadRequestException {
        List<GlobalGroupMapperBean> existingGroups = userBean.getGlobalGroups();
        List<GlobalGroupMapperBean> currentGroups = addGroups(groupNames);
        List<GlobalGroupMapperBean> updatedGroupList = new ArrayList<>();
        if (currentGroups.isEmpty())
            throw new BadRequestException(Translator.toLocale("saml.no.roles"));
        /** Updating the statistics of number of users associated with each group */
        for (GlobalGroupMapperBean groupModel : existingGroups) {
            if (!currentGroups.contains(groupModel)) {
                Optional<GlobalGroupMapperBean> globalGroupModelOpt = globalGroupAbstractRepository
                        .findByGroupName(groupModel.getGroupName());

                GlobalGroupMapperBean globalGroupResponseDTO = globalGroupModelOpt.get();
                if (globalGroupResponseDTO.getAssignedUsersCount() != null) {
                    globalGroupResponseDTO.setAssignedUsersCount(globalGroupResponseDTO.getAssignedUsersCount() - 1);
                }
                globalGroupAbstractRepository.save(globalGroupResponseDTO);
            } else {
                updatedGroupList.add(groupModel);
            }
        }

        for (GlobalGroupMapperBean groupModel : currentGroups) {
            if (!updatedGroupList.contains(groupModel)) {
                Optional<GlobalGroupMapperBean> globalGroupModelOpt = globalGroupAbstractRepository
                        .findByGroupName(groupModel.getGroupName());

                GlobalGroupMapperBean globalGroupResponseDTO = globalGroupModelOpt.get();
                if (globalGroupResponseDTO.getAssignedUsersCount() != null) {
                    globalGroupResponseDTO.setAssignedUsersCount(globalGroupResponseDTO.getAssignedUsersCount() + 1);
                }
                globalGroupAbstractRepository.save(globalGroupResponseDTO);
                updatedGroupList.add(groupModel);
            }
        }
        userBean.setGlobalGroups(updatedGroupList);
        userBean.setGlobalRoles(getRolesInGroup(updatedGroupList));
        return userAbstractRepository.save(userBean);
    }

    private List<GlobalGroupMapperBean> addGroups(List<String> groupNames) {
        List<GlobalGroupMapperBean> groups = new ArrayList<>();
        for (String groupName : groupNames) {
            Optional<GlobalGroupMapperBean> globalGroup =  globalGroupAbstractRepository.findByGroupName(groupName);
            if (globalGroup.isPresent())
                groups.add(globalGroup.get());
        }
        return groups;
    }

    @Override
    public Map<String, String> loginUser(LoginRequest loginRequest)
            throws NoSuchMessageException, BadRequestException, LicenseExpiredException {

        JwtToken accessToken = null;
        JwtToken refreshToken = null;
        Map<String, String> tokenMap = new HashMap<>();
        byte[] byteArray = Base64.decodeBase64(loginRequest.getPassword());
        String decodedPassword = new String(byteArray);
        Optional<UserModelMapperBean> userModelResponseDto = userAbstractRepository
                .findByIdIgnoreCase(loginRequest.getUserId());
        if (userModelResponseDto.isPresent()) {
            loginRequest.setUserId(userModelResponseDto.get().getId());
        }
        AuthUserDetails userContext = null;
        if (checkUserValid(loginRequest.getUserId())) {
            throw new BadRequestException(Translator.toLocale("user.deleteUser"));

        }

        if (enableLdapLogin) {
            log.info("LDAP Authentication is enabled... ");
            // tokenMap = ldapAuthenticationService.ldapUserDetails(loginRequest);

        } else {
            final Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUserId(), decodedPassword));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            userContext = (AuthUserDetails) authentication.getPrincipal();
            accessToken = tokenFactory.generateAccessJwtToken(userContext);
//            if (accessToken == null) {
//                throw new LicenseExpiredException("Licence file is corrupted.");
//            }
            refreshToken = tokenFactory.generateRefreshToken(userContext);
            tokenMap.put(JwtConstants.ApiResponseFields.ACCESS_TOKEN, accessToken.getToken());
            tokenMap.put(JwtConstants.ApiResponseFields.REFRESH_TOKEN, refreshToken.getToken());
            tokenMap.put(JwtConstants.ApiResponseFields.LICENSE_EXPIRED, licenseCheckerService.archonLicenseCheck()?"false":"true");
        }
        auditHelper.LogEvents(loginRequest.getUserId(), Event.SIGN_IN,
                Translator.toLocale("audit.signIn", new String[]{loginRequest.getUserId()}), false);
        return tokenMap;
    }

    @Override
    public TokenResponseDTO generateTokens(HttpServletRequest request, HttpServletResponse response) {

        String tokenPayload = tokenExtractor.extract(request);

        JwtAccessToken rawToken = new JwtAccessToken(tokenPayload);
        JwtRefreshToken jwtRefreshToken = JwtRefreshToken.create(rawToken, tokenSigningKey).orElseThrow(InvalidJwtTokenException::new);

        String jti = jwtRefreshToken.getJti();
        if (!tokenVerifier.verify(jti)) {
            throw new InvalidJwtTokenException();
        }

        String subject = jwtRefreshToken.getSubject();
        UserModelMapperBean user = findByEmailAddress(subject)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + subject));

        if (user.getGlobalGroups() == null)
            throw new InsufficientAuthenticationException("User has no groups assigned");

        AuthUserDetails userDetails = new AuthUserDetails(user);

        final JwtToken accessToken = tokenFactory.generateAccessJwtToken(userDetails);
        final JwtToken refreshToken = tokenFactory.generateRefreshToken(userDetails);

        TokenResponseDTO tokens = TokenResponseDTO.builder().accessToken(accessToken.getToken())
                .refreshToken(refreshToken.getToken()).build();

        return tokens;
    }

    @Data
    private static class ForgotPasswordRequestBody {
        private String emailAddress;
    }

    public void validateSMTP() throws JsonParseException, JsonMappingException, IOException, BadRequestException {
        String smtpModelResponse;
        SMTPResponseDTO smtpdto = null;
        if (url.contains("https")) {
            smtpModelResponse = smtpFeignClient.fetchSMTPModel().get("smtpDetails");
        } else {
            smtpModelResponse = smtpFeignClientHTTP.fetchSMTPModel().get("smtpDetails");
        }
        if (smtpModelResponse != null) {
            smtpdto = new ObjectMapper().readValue(smtpModelResponse, SMTPResponseDTO.class);
        } else {
            throw new BadRequestException(Translator.toLocale("administration.smtpPolicyRequired"));
        }
        if (smtpdto.getHost() == null || smtpdto.getUsername() == null) {
            throw new BadRequestException(Translator.toLocale("administration.smtpPolicyRequired"));
        }

    }

    @Override
    public void generateForgetPasswordLink(String emailAddress) throws BadRequestException, IOException {
        // validate whether SMTP configuration is present or not
        validateSMTP();
        throwIfTrue(isEmpty(emailAddress) || containsWhitespace(emailAddress), INVALID_EMAIL_FORMAT);
        // final String formattedEmailAddress = emailAddress.trim().toLowerCase();
        final Optional<UserModelMapperBean> emailPresentOptional = findByEmailAddress(emailAddress);
        if (!emailPresentOptional.isPresent()) {
            throw new ServerException(INVALID_EMAIL_ADDRESS);
        }
        if (checkUserValid(emailPresentOptional.get().getId())) {
            throw new BadRequestException(Translator.toLocale("user.deleteUser"));
        }
        final Optional<ResetPasswordMapperBean> resetPasswordResponseDTO = resetPasswordAbstractRepository.generateAndStoreResetModel(emailAddress);
        final ResetPasswordMapperBean resetModel = resetPasswordResponseDTO.orElseThrow(() -> new ServerException(FAILED_TO_GEN_RESET_PASS));
        final String resetUrl = String.format("%s?%s=%s", resetPasswordUrl, RESET_KEY_PARAM, resetModel.getResetKey());
        String linkRest = "<html>" + "<head>" + "<a href='" + resetUrl + "' >" + resetUrl + "</a>" + "</head>"
                + "<body>" + "</br>"
                + "<p> <b>Note :</b>  The link will expire in 24 hours, so be sure to use it right away.</p>" + ""
                + "</body>" + "</html>";
        List<String> toEmail = new ArrayList<String>();
        toEmail.add(emailAddress);
        MailNotificationModel mailNotificationModel = MailNotificationModel.builder()
                .emailType(EmailType.SIMPLE_EMAIL.toString())
                .currentUser(emailPresentOptional.get().getFirstName() + " " + emailPresentOptional.get().getLastName())
                .message(String.format(MailConstants.FORGOT_SCRT, linkRest))
                .subject(MailConstants.FORGOT_SCRT_SUBJECT).toEmail(toEmail).build();
        String kafkaString = new ObjectMapper().writeValueAsString(mailNotificationModel);
        messenger.send(sendEmailTopic, kafkaString, kafkaString);
        // Audit

        auditHelper.LogEvents(emailPresentOptional.get().getId(), Event.FORGOT_PASSWORD,
                Translator.toLocale("audit.forgotPassword", new String[]{emailPresentOptional.get().getId()}),
                false);

    }

    @Override
    public ResetPasswordResponseDTO generateResetKey(String resetKey) throws BadRequestException {

        ServerException.throwIfTrue(StringUtils.isEmpty(resetKey), FailureMessages.MISSING_RESET_KEY);
        ResetPasswordRequestDTO resetPasswordDetail = getResetPasswordRequestDTO(resetKey);
        if (resetPasswordDetail == null) {
            throw new BadRequestException(Translator.toLocale("reset.passwordKeyEmpty"));

        }
        if (resetPasswordDetail.getIsLinkAccessByUser() != null && resetPasswordDetail.getIsLinkAccessByUser()) {
            throw new BadRequestException(Translator.toLocale("reset.invalidResetKey"));

        }
        if (checkTokenExpired(resetPasswordDetail.getCreatedAt())) {
            throw new BadRequestException(Translator.toLocale("reset.keyExpired"));
        }

        ResetPasswordResponseDTO response = ResetPasswordResponseDTO.builder()
                .emailAddress(resetPasswordDetail.getEmailAddress())
                .expiredTime(resetPasswordDetail.getExpiredTime())
                .isLinkAccessByUser(resetPasswordDetail.getIsLinkAccessByUser())
                .resetKey(resetPasswordDetail.getResetKey())
                .build();
        return response;
    }

    @Override
    public void generateResetPassword(PasswordResetDTO dto) throws BadRequestException {
        validationForResetPasswordDTO(dto);
        if (!dto.getPassword().equalsIgnoreCase(dto.getConfirmPassword())) {
            throw new BadRequestException(Translator.toLocale("password.mismatch"));
        }
        UserModelMapperBean user = userAbstractRepository.findByEmailAddressIgnoreCase(dto.getEmailAddress()).orElseThrow(() -> new BadRequestException(FailureMessages.INVALID_EMAIL_ADDRESS));
        ResetPasswordRequestDTO resetPasswordDetail = getResetPasswordRequestDTO(dto.getResetKey());
        if(!user.getEmailAddress().equalsIgnoreCase(resetPasswordDetail.getEmailAddress())){
            throw new BadRequestException(Translator.toLocale("reset.misMatchedEmail"));
        }
        Boolean isReset = updateResetPasswordForUser(dto);
        if (!isReset) {
            throw new BadRequestException("Unable to reset the password");
        }
        auditHelper.LogEvents(user.getId(), Event.FORGOT_PASSWORD, Translator.toLocale("audit.updatePassword", new String[]{user.getId()}), false);

    }

    private ResetPasswordRequestDTO getResetPasswordRequestDTO(String resetKey) throws BadRequestException {
        ResetPasswordRequestDTO requestDTOOptional = resetPasswordAbstractRepository.findByResetKey(resetKey);
        if(Objects.isNull(requestDTOOptional)){
            throw new BadRequestException(Translator.toLocale("reset.invalidReset"));
        }
        return requestDTOOptional;
    }

    @Override
    public void logout(String token) throws BadRequestException, JSONException {
        if (StringUtils.isEmpty(token)) {
            throw new BadRequestException("Token is not present ");
        }
        // UserModel uModel = userService.currentUser();
        byte[] byteArray = Base64.decodeBase64(token);
        String decodedPassword = new String(byteArray);
        String split1[] = decodedPassword.split("exp\":", 2);
        String split2[] = split1[1].split("}", 2);
        TokenExpiryDetails details = TokenExpiryDetails.builder().token(token).expiryDateTime(split2[0]).build();
        tokenModelAbstractRepository.save(details);
        String split3[] = decodedPassword.split("exp\":", 2);
        String split4[] = split3[0].split("\"id\":\"", 2);
        String split5[] = split4[1].split("\",", 2);
        String userId = split5[0];

        auditHelper.LogEvents(userId, Event.SIGN_OUT, Translator.toLocale("audit.signOut", new String[]{userId}),
                false);

    }

    @Override
    public boolean isValidEmailAddress(String email) {
        String ePattern = "^[a-zA-Z0-9.!#$%&'*+/=?^_`{|}~-]+@((\\[[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\])|(([a-zA-Z\\-0-9]+\\.)+[a-zA-Z]{2,}))$";
        Pattern pattern = Pattern.compile(ePattern);
        Matcher matcher = pattern.matcher(email);
        return matcher.matches();
    }

    @Override
    public String getAccessToken(String username, String encodedPassword) {
        String token = "";
        try {
            Optional<UserModelMapperBean> userModel = userAbstractRepository.findById(username);
            if (userModel.isPresent()){
                final Authentication authentication = authenticationManager
                        .anonymousUserAuthenticate(userModel.get());
                SecurityContextHolder.getContext().setAuthentication(authentication);
                AuthUserDetails userContext = (AuthUserDetails) authentication.getPrincipal();
                JwtToken jwtToken = tokenFactory.generateAccessJwtTokenForConfig(userContext, true);
                token = jwtToken.getToken();
            } else
                throw new Exception("Invalid user");
        } catch (Exception ex) {
            ExceptionHandler.exception(Translator.toLocale("token.failed"), ex);
        }
        return token;
    }

    @Override
    public void generateCookie(HttpServletResponse response, Map<String, String> tokens) {
        for (String cookieKey : tokens.keySet()) {
            Cookie cookie = new Cookie(cookieKey, tokens.get(cookieKey));
            cookie.setPath(Encode.forJava("/"));
            if (sslEnabled)
                cookie.setSecure(true);
            if (StringUtils.isEmpty(tokens.get(cookieKey)))
                cookie.setMaxAge(0);
            cookie.setHttpOnly(true);
            response.addCookie(cookie);
        }
    }
}
