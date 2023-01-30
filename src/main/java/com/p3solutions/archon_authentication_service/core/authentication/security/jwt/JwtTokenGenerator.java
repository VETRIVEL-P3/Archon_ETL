package com.p3solutions.archon_authentication_service.core.authentication.security.jwt;

import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtAccessToken;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.beans.JwtToken;
import com.p3solutions.archon_authentication_service.core.constants.JwtConstants;
import com.p3solutions.archon_authentication_service.core.user.services.UserService;
import com.p3solutions.common_beans_dto.administration.abstract_repository.AdministrationConfigAbstractRepository;
import com.p3solutions.common_beans_dto.administration.mapper_beans.AdministrationConfigMapperBean;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.common_beans_dto.datasource.abstract_repository.DatasourceProfileAccessAbstractRepository;
import com.p3solutions.common_beans_dto.datasource.mapper_beans.DatasourceProfileAccessMapperBean;
import com.p3solutions.common_beans_dto.global_groups_roles.enums.RoleEnum;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.common_beans_dto.workspace.abstract_repository.WorkspaceProfileAccessAbstractRepository;
import com.p3solutions.common_beans_dto.workspace.mapper_beans.WorkspaceAccessMapperBean;
import com.p3solutions.utility.common_exceptions.ServerException;
import com.p3solutions.utility.internationalization.Translator;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.*;

import static com.p3solutions.archon_authentication_service.core.constants.JwtConstants.REFRESH_TOKEN_ROLE;
import static java.util.stream.Collectors.toList;
import static org.springframework.util.StringUtils.isEmpty;

/**
 * Factory for generating Access and Refresh JWT Tokens
 *
 * @author vishwabhat
 */
@Component
public class JwtTokenGenerator {

    @Value("${jwt.token.issuer}")
    public String tokenIssuer;
    @Value("${jwt.token.signing-key}")
    public String tokenSigningKey;
    @Value("${jwt.access.token.expiration}")
    public String accessTokenExpiration;
    @Value("${jwt.refresh.token.expiration}")
    public String refreshTokenExpiration;
    @Value("${commonAuth.enabled}")
    public boolean isCommonAuthenticationMode;
    @Value("${commonAuth.redirectUrl}")
    public String isCommonAuthenticationLandingUrl;
    @Value("${commonAuth.logoutUrl}")
    public String isCommonAuthenticationLogoutUrl;

    @Autowired
    private DatasourceProfileAccessAbstractRepository datasourceProfileAccessAbstractRepository;
    @Autowired
    private WorkspaceProfileAccessAbstractRepository workspaceProfileAccessAbstractRepository;
    @Autowired
    private AdministrationConfigAbstractRepository administrationConfigAbstractRepository;

    @Autowired
    private UserService userService;

    /**
     * Generates JWT Access Token from the given user data
     *
     * @return Access Token
     */
    public JwtToken generateAccessJwtToken(AuthUserDetails userDetails) {
        Boolean isWorkspaceConfigurationAllowed = false;
        Boolean isDatasourceConfigurationAllowed = false;
        Boolean isOnBoardingAllowed = false;
        Boolean isSystemAdmin = false;
        Boolean isAuditor = false;
        ServerException.throwIfTrue(userDetails == null,
                FailureMessages.MISSING_METHOD_PARAMETER.apply("userDetails"));
        ServerException.throwIfTrue(isEmpty(userDetails.getUsername()),
                FailureMessages.JWT_TOKEN_GEN_FAILED_MISSING_USERNAME);
        ServerException.throwIfTrue((userDetails.getAuthorities() == null || userDetails.getAuthorities().isEmpty()),
                FailureMessages.JWT_TOKEN_GEN_FAILED_EMPTY_AUTHORITIES);

        final UserModelMapperBean userModel = userDetails.getUserModel();
        Claims claims = Jwts.claims().setSubject(userDetails.getName());

        final List<RoleInfo> roleInfoList = userService.getRolesInGroup(userModel.getGlobalGroups()).stream()
                .map(r -> new RoleInfo(r.getId(), r.getRoleName())).collect(toList());
        final List<String> roleInfoName = userService.getRolesInGroup(userModel.getGlobalGroups()).stream()
                .map(r -> new String(r.getRoleName())).collect(toList());
        final UserInfo userInfo = new UserInfo(userModel.getFirstName(), userModel.getLastName(), userModel.getId(),
                userModel.getEmailAddress());

        claims.put(JwtConstants.ApiResponseFields.ROLES, roleInfoList);
        claims.put(JwtConstants.ApiResponseFields.USER, userInfo);
        List<AdministrationConfigMapperBean> administrationConfigMapperBeans = administrationConfigAbstractRepository.findAll();
        if (administrationConfigMapperBeans.isEmpty()) {
            throw new ServerException(Translator.toLocale("user.systemSettingNotUpdated"));
        }
        if (roleInfoName.contains(RoleEnum.ROLE_SYS_ADMIN.toString())) {
            isSystemAdmin = true;
            isWorkspaceConfigurationAllowed = true;
            isDatasourceConfigurationAllowed = true;
        } else {
            if (roleInfoName.contains(RoleEnum.ROLE_WS_MANAGER.toString())) {
                isWorkspaceConfigurationAllowed = true;
            } else {
                isWorkspaceConfigurationAllowed = isWorkspaceAccess(userModel.getId());
            }
            if (roleInfoName.contains(RoleEnum.ROLE_DS_MANAGER.toString())) {
                isDatasourceConfigurationAllowed = true;
            } else {
                isDatasourceConfigurationAllowed = isDatasourceAccess(userModel.getId());
            }
        }
        if (roleInfoName.contains(RoleEnum.ROLE_ONBOARD.toString())) {
            isOnBoardingAllowed = true;
        }
        if (roleInfoName.contains(RoleEnum.ROLE_AUDITOR.toString())) {
            isAuditor = true;
        }
        claims.put("isWorkspaceConfigurationAllowed", isWorkspaceConfigurationAllowed);
        claims.put("isDatasourceConfigurationAllowed", isDatasourceConfigurationAllowed);
        claims.put("isOnBoardingAllowed", isOnBoardingAllowed);
        claims.put("isSystemAdmin", isSystemAdmin);
        claims.put("isAuditor", isAuditor);
        claims.put("isCommonAuthenticationMode",isCommonAuthenticationMode);
        claims.put("isCommonAuthenticationLandingUrl",isCommonAuthenticationLandingUrl);
        claims.put("isCommonAuthenticationLogoutUrl",isCommonAuthenticationLogoutUrl);
        // if user does not have a role of ROLE_SYS_ADMIN then licence check is required
        //roleInfoName.remove("ROLE_SYS_ADMIN");
        if (!roleInfoName.contains(RoleEnum.ROLE_SYS_ADMIN.name())) {
//            LocalDateTime licenceExpiryDate = licenseValidationService.passTokenExpirationTime();
//            if (licenceExpiryDate == null) {
//                return null;
//            }
  //          LocalDateTime currentTime = LocalDateTime.now();
            /*
             * if token validation time exceeds licence expiry time then token will be
             * issued only for a valid period
             */
//            if (currentTime.plusHours(1).isAfter(licenceExpiryDate)) {
//                Integer minutes = 60 - currentTime.getMinute();
//                return new JwtAccessToken(Jwts.builder().setClaims(claims).setIssuer(tokenIssuer)
//                        .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
//                        .setExpiration(
//                                Date.from(currentTime.plusMinutes(minutes).atZone(ZoneId.systemDefault()).toInstant()))
//                        .signWith(SignatureAlgorithm.HS512, tokenSigningKey).compact());
//            }
        }
        LocalDateTime currentTime = LocalDateTime.now();
        return new JwtAccessToken(Jwts.builder().setClaims(claims).setIssuer(tokenIssuer)
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime.plusMinutes(administrationConfigMapperBeans.get(0).getSessionTimeOutInMinutes()).atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, tokenSigningKey).compact());
    }

    /**
     * Generates Refresh token from the given user data
     *
     * @return Refresh Token
     */
    public JwtToken generateRefreshToken(AuthUserDetails userDetails) {
        ServerException.throwIfTrue(userDetails == null,
                FailureMessages.MISSING_METHOD_PARAMETER.apply("userDetails"));
        //ServerException.throwIfTrue(isEmpty(userDetails.getUsername()),
                //FailureMessages.JWT_TOKEN_GEN_FAILED_MISSING_USERNAME);
        LocalDateTime currentTime = LocalDateTime.now();
        Claims claims = Jwts.claims().setSubject(userDetails.getUsername());
        claims.put(JwtConstants.ApiResponseFields.ROLES, Collections.singletonList(REFRESH_TOKEN_ROLE));
        return new JwtAccessToken(
                Jwts.builder().setClaims(claims).setIssuer(tokenIssuer).setId(UUID.randomUUID().toString())
                        .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                        .setExpiration(Date.from(currentTime.plusHours(24).atZone(ZoneId.systemDefault()).toInstant()))
                        .signWith(JwtConstants.SIGNATURE_ALGORITHM, tokenSigningKey).compact());
    }

    /**
     * This access token is used for connecting to the config service as the signing key is different here
     * @param userDetails
     * @return
     */
    public JwtToken generateAccessJwtTokenForConfig(AuthUserDetails userDetails, Boolean modifiedSignKey) {
        Boolean isWorkspaceConfigurationAllowed = false;
        Boolean isDatasourceConfigurationAllowed = false;
        Boolean isOnBoardingAllowed = false;
        Boolean isSystemAdmin = false;
        Boolean isAuditor = false;
        ServerException.throwIfTrue(userDetails == null,
                FailureMessages.MISSING_METHOD_PARAMETER.apply("userDetails"));
        //ServerException.throwIfTrue(isEmpty(userDetails.getUsername()),
                //FailureMessages.JWT_TOKEN_GEN_FAILED_MISSING_USERNAME);
        ServerException.throwIfTrue((userDetails.getAuthorities() == null || userDetails.getAuthorities().isEmpty()),
                FailureMessages.JWT_TOKEN_GEN_FAILED_EMPTY_AUTHORITIES);

        final UserModelMapperBean userModel = userDetails.getUserModel();
        Claims claims = Jwts.claims().setSubject(userDetails.getName());

        final List<RoleInfo> roleInfoList = userService.getRolesInGroup(userModel.getGlobalGroups()).stream()
                .map(r -> new RoleInfo(r.getId(), r.getRoleName())).collect(toList());
        final List<String> roleInfoName = userService.getRolesInGroup(userModel.getGlobalGroups()).stream()
                .map(r -> new String(r.getRoleName())).collect(toList());
        final UserInfo userInfo = new UserInfo(userModel.getFirstName(), userModel.getLastName(), userModel.getId(),
                userModel.getEmailAddress());

        claims.put(JwtConstants.ApiResponseFields.ROLES, roleInfoList);
        claims.put(JwtConstants.ApiResponseFields.USER, userInfo);
        if (roleInfoName.contains(RoleEnum.ROLE_SYS_ADMIN.toString())) {
            isSystemAdmin = true;
            isWorkspaceConfigurationAllowed = true;
            isDatasourceConfigurationAllowed = true;
        } else {
            if (roleInfoName.contains(RoleEnum.ROLE_WS_MANAGER.toString())) {
                isWorkspaceConfigurationAllowed = true;
            } else {
                isWorkspaceConfigurationAllowed = isWorkspaceAccess(userModel.getId());
            }
            if (roleInfoName.contains(RoleEnum.ROLE_DS_MANAGER.toString())) {
                isDatasourceConfigurationAllowed = true;
            } else {
                isDatasourceConfigurationAllowed = isDatasourceAccess(userModel.getId());
            }
        }
        if (roleInfoName.contains(RoleEnum.ROLE_ONBOARD.toString())) {
            isOnBoardingAllowed = true;
        }
        if (roleInfoName.contains(RoleEnum.ROLE_AUDITOR.toString())) {
            isAuditor = true;
        }
        claims.put("isWorkspaceConfigurationAllowed", isWorkspaceConfigurationAllowed);
        claims.put("isDatasourceConfigurationAllowed", isDatasourceConfigurationAllowed);
        claims.put("isOnBoardingAllowed", isOnBoardingAllowed);
        claims.put("isSystemAdmin", isSystemAdmin);
        claims.put("isAuditor", isAuditor);
        claims.put("isCommonAuthenticationMode",isCommonAuthenticationMode);
        claims.put("isCommonAuthenticationLandingUrl",isCommonAuthenticationLandingUrl);
        claims.put("isCommonAuthenticationLogoutUrl",isCommonAuthenticationLogoutUrl);
        String signingKey = tokenSigningKey;
        int tokenExpiry = 60 * 24;
        if (modifiedSignKey) {
            signingKey = "Archon_" + tokenSigningKey;
            tokenExpiry = 10;
        }
        LocalDateTime currentTime = LocalDateTime.now();
        return new JwtAccessToken(Jwts.builder().setClaims(claims).setIssuer(tokenIssuer)
                .setIssuedAt(Date.from(currentTime.atZone(ZoneId.systemDefault()).toInstant()))
                .setExpiration(Date.from(currentTime.plusMinutes(tokenExpiry).atZone(ZoneId.systemDefault()).toInstant()))
                .signWith(SignatureAlgorithm.HS512, signingKey).compact());
    }



    @AllArgsConstructor
    @Data
    @NoArgsConstructor
    @Builder
    public static class RoleInfo {
        private String roleId, roleName;

        public enum Fields {
            roleName, roleId
        }
    }

    @AllArgsConstructor
    @Getter
    @Setter
    @NoArgsConstructor
    @Builder
    public static class UserInfo {

        private String firstName;
        private String lastName;
        private String id;
        private String emailAddress;
    }

    private Boolean isWorkspaceAccess(String userId) {
        Optional<WorkspaceAccessMapperBean> workspaceProfileAccessDto = workspaceProfileAccessAbstractRepository.findbyUserId(userId);
        if (!workspaceProfileAccessDto.isPresent()) {
            return false;
        } else {
            if (hasWSRole(workspaceProfileAccessDto)) {
                return true;
            }
            return false;
        }
    }

    private boolean hasWSRole(Optional<WorkspaceAccessMapperBean> workspaceProfileAccessDto) {
        return (workspaceProfileAccessDto.get().getOwnedWorkspace() != null && !workspaceProfileAccessDto.get().getOwnedWorkspace().isEmpty()) || (workspaceProfileAccessDto.get().getAdminedWorkspace() != null && !workspaceProfileAccessDto.get().getAdminedWorkspace().isEmpty());
    }

    private Boolean isDatasourceAccess(String userId) {
        Optional<DatasourceProfileAccessMapperBean> datasourceProfileAccessDto = datasourceProfileAccessAbstractRepository.findByuserId(userId);
        if (!datasourceProfileAccessDto.isPresent()) {
            return false;
        } else {
            if (hasDSRole(datasourceProfileAccessDto)) {
                return true;
            }
            return false;
        }
    }

    private boolean hasDSRole(Optional<DatasourceProfileAccessMapperBean> datasourceProfileAccessDto) {
        return (datasourceProfileAccessDto.get().getOwnedDSProfiles() != null && !datasourceProfileAccessDto.get().getOwnedDSProfiles().isEmpty()) || (datasourceProfileAccessDto.get().getAdminDSProfiles() != null && !datasourceProfileAccessDto.get().getAdminDSProfiles().isEmpty());
    }

}
