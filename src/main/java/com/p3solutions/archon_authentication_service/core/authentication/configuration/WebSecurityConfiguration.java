package com.p3solutions.archon_authentication_service.core.authentication.configuration;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.p3solutions.archon_authentication_service.core.authentication.filters.CustomCorsFilter;
import com.p3solutions.archon_authentication_service.core.authentication.security.AuthEntryPoint;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.AjaxAuthenticationProvider;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.AjaxLoginProcessingFilter;
import com.p3solutions.archon_authentication_service.core.authentication.security.ajax.handlers.AjaxSuccessHandler;
import com.p3solutions.archon_authentication_service.core.authentication.security.handlers.AuthorizationFailureHandler;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtAuthenticationProvider;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtConfigParameters;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.JwtTokenAuthenticationProcessingFilter;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.PathRequestMatcher;
import com.p3solutions.archon_authentication_service.core.authentication.security.jwt.extractor.TokenExtractor;
import com.p3solutions.archon_authentication_service.core.authentication.security.saml.core.SAMLUserDetailsServiceImpl;
import org.apache.commons.httpclient.HttpClient;
import org.apache.commons.httpclient.MultiThreadedHttpConnectionManager;
import org.apache.velocity.app.VelocityEngine;
import org.opensaml.saml2.metadata.provider.HTTPMetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProvider;
import org.opensaml.saml2.metadata.provider.MetadataProviderException;
import org.opensaml.xml.parse.ParserPool;
import org.opensaml.xml.parse.StaticBasicParserPool;
import org.springframework.beans.factory.DisposableBean;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.core.env.Environment;
import org.springframework.core.io.DefaultResourceLoader;
import org.springframework.core.io.InputStreamResource;
import org.springframework.core.io.Resource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.saml.*;
import org.springframework.security.saml.context.SAMLContextProviderImpl;
import org.springframework.security.saml.key.JKSKeyManager;
import org.springframework.security.saml.key.KeyManager;
import org.springframework.security.saml.log.SAMLDefaultLogger;
import org.springframework.security.saml.metadata.*;
import org.springframework.security.saml.parser.ParserPoolHolder;
import org.springframework.security.saml.processor.*;
import org.springframework.security.saml.util.VelocityFactory;
import org.springframework.security.saml.websso.*;
import org.springframework.security.web.DefaultSecurityFilterChain;
import org.springframework.security.web.FilterChainProxy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.access.channel.ChannelProcessingFilter;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.security.web.authentication.logout.SimpleUrlLogoutSuccessHandler;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;
import org.springframework.security.web.csrf.CsrfFilter;
import org.springframework.security.web.header.writers.StaticHeadersWriter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.util.*;
import java.util.function.Function;

import static java.util.Arrays.asList;

@Configuration
@EnableWebSecurity
@EnableGlobalMethodSecurity(securedEnabled = true)
public class WebSecurityConfiguration {
	/**
	 * Setting up the order as 1 for the SAML authentication
	 * Configuration class for enabling the SAML web security
	 * This class will be initialised only if the the saml.enabled property is set to true
	 */
	@Order(1)
	@Configuration
	@ConditionalOnProperty(name = "saml.enabled", havingValue = "true")
	public static class SAMLWebSecurityConfiguration extends WebSecurityConfigurerAdapter implements InitializingBean, DisposableBean {
		@Autowired
		Environment environment;

		private Timer backgroundTaskTimer;
		private MultiThreadedHttpConnectionManager multiThreadedHttpConnectionManager;

		public void init() {
			this.backgroundTaskTimer = new Timer(true);
			this.multiThreadedHttpConnectionManager = new MultiThreadedHttpConnectionManager();
		}

		public void shutdown() {
			this.backgroundTaskTimer.purge();
			this.backgroundTaskTimer.cancel();
			this.multiThreadedHttpConnectionManager.shutdown();
		}

		@Autowired
		private SAMLUserDetailsServiceImpl samlUserDetailsServiceImpl;

		// Initialization of the velocity engine
		@Bean
		public VelocityEngine velocityEngine() {
			return VelocityFactory.getEngine();
		}

		// XML parser pool needed for OpenSAML parsing
		@Bean(initMethod = "initialize")
		public StaticBasicParserPool parserPool() {
			return new StaticBasicParserPool();
		}

		@Bean(name = "parserPoolHolder")
		public ParserPoolHolder parserPoolHolder() {
			return new ParserPoolHolder();
		}

		// Bindings, encoders and decoders used for creating and parsing messages
		@Bean
		public HttpClient httpClient() {
			return new HttpClient(this.multiThreadedHttpConnectionManager);
		}

		// SAML Authentication Provider responsible for validating of received SAML
		// messages
		@Bean
		public SAMLAuthenticationProvider samlAuthenticationProvider() {
			SAMLAuthenticationProvider samlAuthenticationProvider = new SAMLAuthenticationProvider();
			samlAuthenticationProvider.setUserDetails(samlUserDetailsServiceImpl);
			samlAuthenticationProvider.setForcePrincipalAsString(false);
			return samlAuthenticationProvider;
		}

		// Provider of default SAML Context
		@Bean
		public SAMLContextProviderImpl contextProvider() {
			return new SAMLContextProviderImpl();
		}

		// Initialization of OpenSAML library
		@Bean
		public static SAMLBootstrap sAMLBootstrap() {
			return new SAMLBootstrap();
		}

		// Logger for SAML messages and events
		@Bean
		public SAMLDefaultLogger samlLogger() {
			return new SAMLDefaultLogger();
		}

		// SAML 2.0 WebSSO Assertion Consumer
		@Bean
		public WebSSOProfileConsumer webSSOprofileConsumer() {
			return new WebSSOProfileConsumerImpl();
		}

		// SAML 2.0 Holder-of-Key WebSSO Assertion Consumer
		@Bean
		public WebSSOProfileConsumerHoKImpl hokWebSSOprofileConsumer() {
			return new WebSSOProfileConsumerHoKImpl();
		}

		// SAML 2.0 Web SSO profile
		@Bean
		public WebSSOProfile webSSOprofile() {
			return new WebSSOProfileImpl();
		}

		// SAML 2.0 Holder-of-Key Web SSO profile
		@Bean
		public WebSSOProfileConsumerHoKImpl hokWebSSOProfile() {
			return new WebSSOProfileConsumerHoKImpl();
		}

		// SAML 2.0 ECP profile
		@Bean
		public WebSSOProfileECPImpl ecpprofile() {
			return new WebSSOProfileECPImpl();
		}

		@Bean
		public SingleLogoutProfile logoutprofile() {
			return new SingleLogoutProfileImpl();
		}

		// Central storage of cryptographic keys
		@Bean
		public KeyManager keyManager() throws FileNotFoundException {
			DefaultResourceLoader loader = new DefaultResourceLoader();
			Resource storeFile = new InputStreamResource(new FileInputStream(
					environment.getProperty("saml.security.keyfile")
			));
			String storePass = environment.getRequiredProperty("saml.security.keyfile-password");
			Map<String, String> passwords = new HashMap<String, String>();
			passwords.put(environment.getRequiredProperty("saml.security.keyfile-key"),
					environment.getRequiredProperty("saml.security.keyfile-key-password"));
			String defaultKey = environment.getRequiredProperty("saml.security.default-key");
			return new JKSKeyManager(storeFile, storePass, passwords, defaultKey);
		}

		@Bean
		public WebSSOProfileOptions defaultWebSSOProfileOptions() {
			WebSSOProfileOptions webSSOProfileOptions = new WebSSOProfileOptions();
			webSSOProfileOptions.setIncludeScoping(false);
			return webSSOProfileOptions;
		}

		// Entry point to initialize authentication, default values taken from
		// properties file
		@Bean
		public SAMLEntryPoint samlEntryPoint() {
			SAMLEntryPoint samlEntryPoint = new SAMLEntryPoint();
			samlEntryPoint.setDefaultProfileOptions(defaultWebSSOProfileOptions());
			return samlEntryPoint;
		}

		// Setup advanced info about metadata
		@Bean
		public ExtendedMetadata extendedMetadata() {
			ExtendedMetadata extendedMetadata = new ExtendedMetadata();
			extendedMetadata.setIdpDiscoveryEnabled(false);
			extendedMetadata.setSigningAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
			extendedMetadata.setSignMetadata(true);
			extendedMetadata.setEcpEnabled(true);
			return extendedMetadata;
		}

		// IDP Discovery Service
		@Bean
		public SAMLDiscovery samlIDPDiscovery() {
			SAMLDiscovery idpDiscovery = new SAMLDiscovery();
			idpDiscovery.setIdpSelectionPath("/saml/discovery");
			return idpDiscovery;
		}

		@Bean
		@Qualifier("idp")
		public ExtendedMetadataDelegate idpMetadataProvider()
				throws MetadataProviderException {
			String metadataUrl = environment.getRequiredProperty("saml.idp.auth-server-url") +
					environment.getRequiredProperty("saml.idp.metadata-descriptor");
			HTTPMetadataProvider httpMetadataProvider = new HTTPMetadataProvider(
					this.backgroundTaskTimer, httpClient(), metadataUrl);
			httpMetadataProvider.setParserPool(parserPool());
			ExtendedMetadataDelegate extendedMetadataDelegate =
					new ExtendedMetadataDelegate(httpMetadataProvider, extendedMetadata());
			extendedMetadataDelegate.setMetadataTrustCheck(true);
			extendedMetadataDelegate.setMetadataRequireSignature(false);
			backgroundTaskTimer.purge();
			return extendedMetadataDelegate;
		}

		// IDP Metadata configuration - paths to metadata of IDPs in circle of trust
		// is here
		// Do no forget to call iniitalize method on providers
		@Bean
		@Qualifier("metadata")
		public CachingMetadataManager metadata() throws MetadataProviderException {
			List<MetadataProvider> providers = new ArrayList<MetadataProvider>();
			providers.add(idpMetadataProvider());
			return new CachingMetadataManager(providers);
		}

		// Filter automatically generates default SP metadata
		@Bean
		public MetadataGenerator metadataGenerator() throws FileNotFoundException {
			MetadataGenerator metadataGenerator = new MetadataGenerator();
			metadataGenerator.setEntityId(environment.getRequiredProperty("saml.idp.entity-id"));
			metadataGenerator.setExtendedMetadata(extendedMetadata());
			metadataGenerator.setIncludeDiscoveryExtension(false);
			metadataGenerator.setKeyManager(keyManager());
			return metadataGenerator;
		}

		// The filter is waiting for connections on URL suffixed with filterSuffix
		// and presents SP metadata there
		@Bean
		public MetadataDisplayFilter metadataDisplayFilter() {
			return new MetadataDisplayFilter();
		}

		// Handler deciding where to redirect user after successful login
		@Bean
		public SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler() {
			SavedRequestAwareAuthenticationSuccessHandler successRedirectHandler =
					new SavedRequestAwareAuthenticationSuccessHandler();
			successRedirectHandler.setDefaultTargetUrl("/saml/landing");
			return successRedirectHandler;
		}

		// Handler deciding where to redirect user after failed login
		@Bean
		public SimpleUrlAuthenticationFailureHandler authenticationFailureHandler() {
			SimpleUrlAuthenticationFailureHandler failureHandler =
					new SimpleUrlAuthenticationFailureHandler();
			failureHandler.setUseForward(true);
			failureHandler.setDefaultFailureUrl("/error");
			return failureHandler;
		}

		@Bean
		public SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter() throws Exception {
			SAMLWebSSOHoKProcessingFilter samlWebSSOHoKProcessingFilter = new SAMLWebSSOHoKProcessingFilter();
			samlWebSSOHoKProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
			samlWebSSOHoKProcessingFilter.setAuthenticationManager(authenticationManager());
			samlWebSSOHoKProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
			return samlWebSSOHoKProcessingFilter;
		}

		// Processing filter for WebSSO profile messages
		@Bean
		public SAMLProcessingFilter samlWebSSOProcessingFilter() throws Exception {
			SAMLProcessingFilter samlWebSSOProcessingFilter = new SAMLProcessingFilter();
			samlWebSSOProcessingFilter.setAuthenticationManager(authenticationManager());
			samlWebSSOProcessingFilter.setAuthenticationSuccessHandler(successRedirectHandler());
			samlWebSSOProcessingFilter.setAuthenticationFailureHandler(authenticationFailureHandler());
			return samlWebSSOProcessingFilter;
		}

		@Bean
		public MetadataGeneratorFilter metadataGeneratorFilter() throws FileNotFoundException {
			return new MetadataGeneratorFilter(metadataGenerator());
		}

		// Handler for successful logout
		@Bean
		public SimpleUrlLogoutSuccessHandler successLogoutHandler() {
			SimpleUrlLogoutSuccessHandler successLogoutHandler = new SimpleUrlLogoutSuccessHandler();
			successLogoutHandler.setDefaultTargetUrl("/");
			return successLogoutHandler;
		}

		// Logout handler terminating local session
		@Bean
		public SecurityContextLogoutHandler logoutHandler() {
			SecurityContextLogoutHandler logoutHandler =
					new SecurityContextLogoutHandler();
			logoutHandler.setInvalidateHttpSession(true);
			logoutHandler.setClearAuthentication(true);
			return logoutHandler;
		}

		// Filter processing incoming logout messages
		// First argument determines URL user will be redirected to after successful
		// global logout
		@Bean
		public SAMLLogoutProcessingFilter samlLogoutProcessingFilter() {
			return new SAMLLogoutProcessingFilter(successLogoutHandler(),
					logoutHandler());
		}

		// Overrides default logout processing filter with the one processing SAML
		// messages
		@Bean
		public SAMLLogoutFilter samlLogoutFilter() {
			return new SAMLLogoutFilter(successLogoutHandler(),
					new LogoutHandler[] { logoutHandler() },
					new LogoutHandler[] { logoutHandler() });
		}

		// Bindings
		private ArtifactResolutionProfile artifactResolutionProfile() {
			final ArtifactResolutionProfileImpl artifactResolutionProfile =
					new ArtifactResolutionProfileImpl(httpClient());
			artifactResolutionProfile.setProcessor(new SAMLProcessorImpl(soapBinding()));
			return artifactResolutionProfile;
		}

		@Bean
		public HTTPArtifactBinding artifactBinding(ParserPool parserPool, VelocityEngine velocityEngine) {
			return new HTTPArtifactBinding(parserPool, velocityEngine, artifactResolutionProfile());
		}

		@Bean
		public HTTPSOAP11Binding soapBinding() {
			return new HTTPSOAP11Binding(parserPool());
		}

		@Bean
		public HTTPPostBinding httpPostBinding() {
			return new HTTPPostBinding(parserPool(), velocityEngine());
		}

		@Bean
		public HTTPRedirectDeflateBinding httpRedirectDeflateBinding() {
			return new HTTPRedirectDeflateBinding(parserPool());
		}

		@Bean
		public HTTPSOAP11Binding httpSOAP11Binding() {
			return new HTTPSOAP11Binding(parserPool());
		}

		@Bean
		public HTTPPAOS11Binding httpPAOS11Binding() {
			return new HTTPPAOS11Binding(parserPool());
		}

		// Processor
		@Bean
		public SAMLProcessorImpl processor() {
			Collection<SAMLBinding> bindings = new ArrayList<SAMLBinding>();
			bindings.add(httpRedirectDeflateBinding());
			bindings.add(httpPostBinding());
			bindings.add(artifactBinding(parserPool(), velocityEngine()));
			bindings.add(httpSOAP11Binding());
			bindings.add(httpPAOS11Binding());
			return new SAMLProcessorImpl(bindings);
		}

		/**
		 * Define the security filter chain in order to support SSO Auth by using SAML 2.0
		 *
		 * @return Filter chain proxy
		 * @throws Exception
		 */
		@Bean
		public FilterChainProxy samlFilter() throws Exception {
			List<SecurityFilterChain> chains = new ArrayList<SecurityFilterChain>();
			chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(environment.getRequiredProperty("saml.url.entry-point")),
					samlEntryPoint()));
			chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(environment.getRequiredProperty("saml.url.logout")),
					samlLogoutFilter()));
			/* chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/metadata/**"),
					metadataDisplayFilter())); */
			chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(environment.getRequiredProperty("saml.url.consumer-post-binding")),
					samlWebSSOProcessingFilter()));
			/* chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/SSOHoK/**"),
					samlWebSSOHoKProcessingFilter())); */
			chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher(environment.getRequiredProperty("saml.url.single-logout")),
					samlLogoutProcessingFilter()));
			/* chains.add(new DefaultSecurityFilterChain(new AntPathRequestMatcher("/saml/discovery/**"),
					samlIDPDiscovery())); */
			return new FilterChainProxy(chains);
		}

		/**
		 * Returns the authentication manager currently used by Spring.
		 * It represents a bean definition with the aim allow wiring from
		 * other classes performing the Inversion of Control (IoC).
		 *
		 * @throws  Exception
		 */

		@Bean
		@Override
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		/**
		 * Defines the web based security configuration.
		 *
		 * @param   http It allows configuring web based security for specific http requests.
		 * @throws  Exception
		 */
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
					.antMatcher("/saml/**")
					.authorizeRequests()
					.anyRequest().authenticated();
			http
					.httpBasic()
					.authenticationEntryPoint(samlEntryPoint());
			http
					.addFilterBefore(metadataGeneratorFilter(), ChannelProcessingFilter.class)
					.addFilterAfter(samlFilter(), BasicAuthenticationFilter.class)
					.addFilterBefore(samlFilter(), CsrfFilter.class);
			http
					.logout()
					.disable();	// The logout procedure is already handled by SAML filters.
		}

		/**
		 * Sets a custom authentication provider.
		 *
		 * @param   auth SecurityBuilder used to create an AuthenticationManager.
		 * @throws  Exception
		 */
		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth
					.authenticationProvider(samlAuthenticationProvider());
		}

		@Override
		public void afterPropertiesSet() throws Exception {
			init();
		}

		@Override
		public void destroy() throws Exception {
			shutdown();
		}
	}

	/**
	 * providing low priority to the in memory authentication
	 * Configuration class for the In memory (database user) web security
	 */
	@Order(2)
	@Configuration
	@ConditionalOnProperty(name = "saml.enabled", havingValue = "false")
	public static class InMemoryWebSecurityConfiguration extends WebSecurityConfigurerAdapter {
		private static final Function<String, String> PATH_URL = (String resource) -> String.format("%s/**", resource);
		private static final String API_ROOT_URL = PATH_URL.apply("");
		private static final String AUTH_LOGIN_URL = "/authentication-management/sign-in";
		private static final String AUTH_URL_FORMAT = PATH_URL.apply("/authentication-management");
		private static final String ROOT_URL = "/";
		private static final String ERROR_URL = "/error";
		private static final String PUBLIC_URL = "/public/**";
		private static final String ADMIN_PATH_URL = PATH_URL.apply("/admin");
		private static final String DATA_ANALYZER_URL = "/dataAnalyzer/**";
		private static final String METALYZER_MEMORY_URL = PATH_URL.apply("/metalyzer/checkForAvailableMemory");
		private static final String LICENSE_UPLOAD_URL = "/license/**";
		private static final String SAML_URL = "/saml/**";

		@Autowired
		private UserDetailsService userDetailsService;

		@Autowired
		private AuthEntryPoint authEntryPoint;

		@Autowired
		private JwtAuthenticationProvider jwtAuthenticationProvider;

		@Autowired
		private AjaxAuthenticationProvider ajaxAuthenticationProvider;

		@Autowired
		private TokenExtractor tokenExtractor;

		@Autowired
		private BCryptPasswordEncoder bcryptPasswordEncoder;

		@Autowired
		private AuthenticationManager authenticationManager;

		@Autowired
		private AjaxSuccessHandler ajaxSuccessHandler;

		@Qualifier("ajaxFailureHandler")
		private AuthenticationFailureHandler ajaxFailureHandler;

		@Qualifier("jwtFailureHandler")
		private AuthenticationFailureHandler jwtFailureHandler;

		@Autowired
		private ObjectMapper objectMapper;


		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(jwtAuthenticationProvider).authenticationProvider(ajaxAuthenticationProvider)
					.userDetailsService(userDetailsService).passwordEncoder(bcryptPasswordEncoder);
		}

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			// We don't need CSRF for JWT based authentication
			http.csrf().disable()
					// Handle authorization attempts
					.exceptionHandling().accessDeniedHandler(accessDeniedHandler(objectMapper))
					.authenticationEntryPoint(authEntryPoint)
					// session won't be used to store user's state.
					.and().sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					// Authorization requests Configuration
					.and().authorizeRequests()
//				.and().addFilterBefore(ajaxLoginProcessingFilter(AUTH_LOGIN_URL), UsernamePasswordAuthenticationFilter.class);
//		 Allow the following URL patterns without authorization
					.antMatchers(AUTH_URL_FORMAT, PUBLIC_URL, ERROR_URL, METALYZER_MEMORY_URL, API_ROOT_URL, SAML_URL).permitAll()
//				// Allow the following URL pattern with Authority of Admin
//				.antMatchers(ADMIN_PATH_URL)
//				.hasAnyAuthority(GlobalRoleConstants.ADMIN_ROLE, GlobalRoleConstants.ADMIN_DB_ROLE,
//						GlobalRoleConstants.SUPER_ADMIN_ROLE)
					// Allow the following URL patterns with authentication
//					.antMatchers(API_ROOT_URL).authenticated()
					.and()
//				// Filter to validate CORS requests
					.addFilterBefore(new CustomCorsFilter(), UsernamePasswordAuthenticationFilter.class)
//				// Filter to validate ajax requests
//				.addFilterBefore(ajaxLoginProcessingFilter(AUTH_LOGIN_URL), UsernamePasswordAuthenticationFilter.class)
//				.addFilterBefore(
//						new ServiceActionAuthorisationFilter(userServiceActionService, serviceActionRepository),
//						BasicAuthenticationFilter.class)
					.addFilterBefore(jwtTokenAuthenticationProcessingFilter(
							asList(AUTH_URL_FORMAT, ERROR_URL, ROOT_URL, PUBLIC_URL, METALYZER_MEMORY_URL, SAML_URL), API_ROOT_URL),
							UsernamePasswordAuthenticationFilter.class)
					.headers().httpStrictTransportSecurity().includeSubDomains(true).maxAgeInSeconds(31536000).and()
					.addHeaderWriter(new StaticHeadersWriter("X-Content-Security-Policy", "script-src 'self'"));
		}

		@Bean
		public AccessDeniedHandler accessDeniedHandler(ObjectMapper mapper) {
			return new AuthorizationFailureHandler(mapper);
		}

		private JwtTokenAuthenticationProcessingFilter jwtTokenAuthenticationProcessingFilter(List<String> pathsToSkip,
																							  String patternToAllow) {

			PathRequestMatcher matcher = new PathRequestMatcher(pathsToSkip, patternToAllow);

			JwtTokenAuthenticationProcessingFilter filter = new JwtTokenAuthenticationProcessingFilter(jwtFailureHandler,
					tokenExtractor, matcher);

			filter.setAuthenticationManager(authenticationManager);

			return filter;
		}

		@Bean
		@Override
		@ConditionalOnProperty(name = "saml.enabled", havingValue = "false")
		public AuthenticationManager authenticationManagerBean() throws Exception {
			return super.authenticationManagerBean();
		}

		private AjaxLoginProcessingFilter ajaxLoginProcessingFilter(String patternToProcess) {
			AjaxLoginProcessingFilter filter = new AjaxLoginProcessingFilter(patternToProcess, ajaxSuccessHandler,
					ajaxFailureHandler, objectMapper);
			filter.setAuthenticationManager(authenticationManager);
			return filter;
		}

		@Bean
		public BCryptPasswordEncoder bCryptPasswordEncoder() {
			return new BCryptPasswordEncoder();
		}

		@Bean("jwtConfigParameters")
		public JwtConfigParameters jwtConfigParameters() {
			JwtConfigParameters settings = new JwtConfigParameters();
			settings.setRefreshTokenExpTime(JwtConfigConstants.REFRESH_TOKEN_EXP_TIME);
			settings.setTokenExpirationTime(JwtConfigConstants.TOKEN_EXPIRATION_TIME);
			settings.setTokenIssuer(JwtConfigConstants.JWT_TOKEN_ISSUER);
			settings.setTokenSigningKey(JwtConfigConstants.JWT_TOKEN_SIGNING_KEY);
			return settings;
		}

		private static class JwtConfigConstants {
			private JwtConfigConstants() {
			}

			static final int REFRESH_TOKEN_EXP_TIME = 100;
			static final int TOKEN_EXPIRATION_TIME = 15;
			static final String JWT_TOKEN_ISSUER = "Application";
			static final String JWT_TOKEN_SIGNING_KEY = "1234567890#application";
		}
		@Override
		public void configure(WebSecurity web) throws Exception {
			web.ignoring().antMatchers("/v2/api-docs",
					"/configuration/ui",
					"/swagger-resources/**",
					"/configuration/security",
					"/swagger-ui.html",
					"/webjars/**");
		}
	}

//	@Bean
//	@Override
//	public AuthenticationManager authenticationManagerBean() throws Exception {
//		return super.authenticationManagerBean();
//	}
}
