package com.p3solutions.archon_authentication_service.core.authentication.security.saml.controllers;

import com.p3solutions.archon_authentication_service.core.audit.AuditHelper;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.service.SamlUserService;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.stereotypes.CurrentUser;
import com.p3solutions.common_beans_dto.audit.enums.Event;
import com.p3solutions.common_beans_dto.users.abstract_repository.UserAbstractRepository;
import com.p3solutions.common_beans_dto.users.mapper_beans.UserModelMapperBean;
import com.p3solutions.utility.internationalization.Translator;
import org.apache.commons.lang.StringUtils;
import org.owasp.encoder.Encode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.saml.metadata.MetadataManager;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Optional;
import java.util.Set;

/**
 * Controller for routing the SAML response to the Archon UI
 * this controller will be initialized only when the saml.enabled proeprty is set to true
 */
@Controller
@RequestMapping("/saml")
@ConditionalOnProperty(name = "saml.enabled", havingValue = "true")
public class SSOController {

	private static final Logger LOG = LoggerFactory.getLogger(SSOController.class);

	@Value("${server.ssl.enabled:false}")
	private Boolean sslEnabled;

	@Autowired
	private MetadataManager metadata;

	@Autowired
	UserAbstractRepository userAbstractRepository;

	@Autowired
	private SamlUserService samlUserService;

	@Autowired
	private AuditHelper auditHelper;

	@Value("${saml.client.redirect-url}")
	private String uiRedirectUrl;

	@RequestMapping(value = "/discovery", method = RequestMethod.GET)
	public String idpSelection(HttpServletRequest request, Model model) {
		Authentication auth = SecurityContextHolder.getContext().getAuthentication();
		if (auth == null)
			LOG.debug("Current authentication instance from security context is null");
		else
			LOG.debug("Current authentication instance from security context: "
					+ this.getClass().getSimpleName());
		if (auth == null || (auth instanceof AnonymousAuthenticationToken)) {
			Set<String> idps = metadata.getIDPEntityNames();
			for (String idp : idps)
				LOG.info("Configured Identity Provider for SSO: " + idp);
			model.addAttribute("idps", idps);
			return "pages/discovery";
		} else {
			LOG.warn("The current user is already logged.");
			return "redirect:/saml/landing";
		}
	}

	@RequestMapping("/landing")
	public void landing(@CurrentUser User user, HttpServletResponse response) throws IOException {
		UserModelMapperBean userBean = null;
		try {
			Optional<UserModelMapperBean> userModel = userAbstractRepository.findByIdAndType(user.getUsername(), "SAML_SSO");
			if (userModel.isPresent()){
				userBean = userModel.get();
				userBean = samlUserService.updateUserRoles(user, userBean);
				try {
					auditHelper.LogEvents(userModel.get().getId(), Event.SIGN_IN, Translator.toLocale("audit.signIn.saml",
							new String[]{userModel.get().getEmailAddress(), userModel.get().getId()}), false);
				} catch (Exception e){
					LOG.error(e.getMessage());
				}
			} else {
				userBean = samlUserService.createSAMLUserEntry(user);
			}
			String token = samlUserService.generateToken(userBean, "accessToken");
			String refreshToken = samlUserService.generateToken(userBean, "refreshToken");
			response.addCookie(createCookie("accessToken", token));
			response.addCookie(createCookie("refreshToken", refreshToken));
			// TODO VERACODE_ISSUE
			//response.sendRedirect(Encode.forJava(uiRedirectUrl));
			response.sendRedirect(uiRedirectUrl);
		} catch (Exception e) {
			LOG.error("Saml Login error :"+ e.getMessage(),e);
			response.addCookie(createCookie("accessToken", StringUtils.EMPTY));
			response.addCookie(createCookie("refreshToken", StringUtils.EMPTY));
			// TODO VERACODE_ISSUE
			//response.sendRedirect(Encode.forJava(uiRedirectUrl));
			response.sendRedirect(uiRedirectUrl);
		}
//		return "pages/landing";
	}

	private Cookie createCookie(String key, String value) {
		Cookie cookie = new Cookie(key, value);
		cookie.setPath("/");
		if (sslEnabled)
			cookie.setSecure(true);
		cookie.setHttpOnly(true);
		return cookie;
	}
}
