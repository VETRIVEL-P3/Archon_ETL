package com.p3solutions.archon_authentication_service.core.authentication.security.ajax;


import com.p3solutions.archon_authentication_service.core.audit.AuditHelper;
import com.p3solutions.common_beans_dto.audit.enums.Event;
import com.p3solutions.common_beans_dto.authentication.beans.AuthUserDetails;
import com.p3solutions.common_beans_dto.common_constants.FailureMessages;
import com.p3solutions.common_beans_dto.global_groups_roles.mapper_beans.GlobalGroupMapperBean;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.internationalization.Translator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import java.util.Calendar;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Component
public class AjaxAuthenticationProvider implements AuthenticationProvider {
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder();
    //private final UserService userService;
    @Autowired
    private UserAbstractRepository userAbstractRepository;

    @Value(value = "${kafka.topic.name.send-email}")
    private String sendEmailTopic;

    @Value(value = "${signInUrl.url}")
    private String signIn;

    @Autowired
    private AuditHelper auditHelper;

    private String EVENT_DETAILS;

//	@Autowired
//	public AjaxAuthenticationProvider(final UserService userService) {
//		this.userService = userService;
//		this.encoder = new BCryptPasswordEncoder();
//	}

    @Override
    public Authentication authenticate(Authentication authentication) {
        Assert.notNull(authentication, "No authentication data provided");

        String userId = (String) authentication.getPrincipal();
        String password = (String) authentication.getCredentials();
        Integer count = 1;
        String responseMessage = "";

        UserModelMapperBean user = userAbstractRepository.findById(userId)
                .orElseThrow(() -> new UsernameNotFoundException(FailureMessages.INVALID_USER_ID));

        Date PerviousDate = new Date(user.getUpdatedAt());
        Calendar calUpdatedAt = Calendar.getInstance();
        calUpdatedAt.setTime(PerviousDate);

        Date currentDate = new Date();
        Calendar calCurrent = Calendar.getInstance();
        calCurrent.setTime(currentDate);

        if (calCurrent.getTime().after(calUpdatedAt.getTime())) {
            if (!encoder.matches(password, user.getPassword())) {

                if (user.getAttemptCount() == null) {
                    user.setAttemptCount(count);
                } else {
                    user.setAttemptCount(user.getAttemptCount() + count);
                }
                if (user.getAttemptCount() <= 3) {
                    user.setUpdatedAt(System.currentTimeMillis() / 1000);
                    userAbstractRepository.save(user);
                    auditHelper.LogEvents(userId, Event.SIGN_IN, Translator.toLocale("audit.signIn.incorrect", new String[]{user.getId()}), false);
                    throw new BadCredentialsException(FailureMessages.INVALID_CREDENTIALS);
                }
                user.setUpdatedAt(System.currentTimeMillis() / 1000);
                userAbstractRepository.save(user);

            } else {
                user.setAttemptCount(0);
                user.setUpdatedAt(System.currentTimeMillis() / 1000);
                userAbstractRepository.save(user);
            }

            if (user.getAttemptCount() != null && user.getAttemptCount() > 3) {
                switch (user.getAttemptCount()) {
                    case 4:
                        calCurrent.add(Calendar.SECOND, 30);
                        responseMessage = "30 seconds.";
                        break;
                    case 5:
                        calCurrent.add(Calendar.MINUTE, 2);
                        responseMessage = "2 minute.";
                        break;
                    case 6:
                        calCurrent.add(Calendar.MINUTE, 5);
                        responseMessage = "5 minute";
                        break;
                    case 7:
                        calCurrent.add(Calendar.MINUTE, 30);
                        responseMessage = "30 minute";
                        break;
                    case 8:
                        calCurrent.add(Calendar.HOUR_OF_DAY, 1);
                        responseMessage = "1 hour.";
                        break;
                    case 9:
                        calCurrent.add(Calendar.HOUR_OF_DAY, 8);
                        responseMessage = "8 hour.";
                        break;
                    default:
                        calCurrent.add(Calendar.DAY_OF_WEEK, 1);
                        responseMessage = "24 hour.";
                        break;
                }
            }
            if (user.getAttemptCount() != null && user.getAttemptCount() > 3) {
                user.setUpdatedAt(calCurrent.getTimeInMillis());
                user.setLockedDuration(calCurrent.getTimeInMillis());
                user.setAccountLocked(true);
                user.setAttemptCount(user.getAttemptCount());
                userAbstractRepository.save(user);
                auditHelper.LogEvents(userId, Event.USER_ACCOUNT_LOCKED, Translator.toLocale("audit.accountLocked", new String[]{user.getId()}), false);
                throw new BadCredentialsException("Try after " + responseMessage);
            }

        } else {
            switch (user.getAttemptCount()) {
                case 4:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                case 5:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                case 6:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                case 7:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                case 8:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                case 9:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
                default:
                    throw new BadCredentialsException(
                            "Account has been lock down due to consecutive login failure. Please try after  "
                                    + timeDiff(calUpdatedAt.getTime().getTime() - calCurrent.getTime().getTime()));
            }
        }

        if (user.getAccountLocked()) {
            throw new BadCredentialsException(FailureMessages.ACCOUNT_LOCKED);
        }
        if (user.getAccessRevoked()) {
            throw new BadCredentialsException(FailureMessages.ACCESS_REVOKED);
        }
        List<GrantedAuthority> authorities = null;
        for (GlobalGroupMapperBean userGroup : user.getGlobalGroups()) {
            if (userGroup.getGlobalRoles().isEmpty())
                throw new InsufficientAuthenticationException("User has no roles assigned");

            authorities = userGroup.getGlobalRoles().stream()
                    .map(authority -> new SimpleGrantedAuthority(authority.getRoleName())).collect(Collectors.toList());
        }

        return new UsernamePasswordAuthenticationToken(new AuthUserDetails(user), null, authorities);
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication));
    }


    public static String timeDiff(long diff) {
        int diffDays = (int) (diff / (24 * 60 * 60 * 1000));
        String dateFormat = "";
        if (diffDays > 0) {
            dateFormat += diffDays + " days ";
            return dateFormat;
        }
        diff -= diffDays * (24 * 60 * 60 * 1000);

        int diffhours = (int) (diff / (60 * 60 * 1000));
        if (diffhours > 0) {
            dateFormat += leftNumPadding(diffhours, 2) + " hours ";
            return dateFormat;
        } else if (dateFormat.length() > 0) {
            dateFormat += "00 hours ";
        }
        diff -= diffhours * (60 * 60 * 1000);

        int diffmin = (int) (diff / (60 * 1000));
        if (diffmin > 0) {
            dateFormat += leftNumPadding(diffmin, 2) + " minutes ";
            return dateFormat;
        } else if (dateFormat.length() > 0) {
            dateFormat += "00 minutes ";
        }

        diff -= diffmin * (60 * 1000);

        int diffsec = (int) (diff / (1000));
        if (diffsec > 0) {
            dateFormat += leftNumPadding(diffsec, 2) + " seconds ";
            return dateFormat;
        } else if (dateFormat.length() > 0) {
            dateFormat += "00 seconds ";
        }
        return "few seconds";
    }

    private static String leftNumPadding(int str, int num) {
        return String.format("%0" + num + "d", str);
    }

    /**
     * Authentication for the config service supported token (Anonymous user)
     * @param user
     * @return
     */
    public Authentication anonymousUserAuthenticate(UserModelMapperBean user) {
        List<GrantedAuthority> authorities = null;
        for (GlobalGroupMapperBean userGroup : user.getGlobalGroups()) {
            if (userGroup.getGlobalRoles().isEmpty())
                throw new InsufficientAuthenticationException("User has no roles assigned");

            authorities = userGroup.getGlobalRoles().stream()
                    .map(authority -> new SimpleGrantedAuthority(authority.getRoleName())).collect(Collectors.toList());
        }
        return new UsernamePasswordAuthenticationToken(new AuthUserDetails(user), null, authorities);
    }
}
