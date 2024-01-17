package com.ideatec.oauth2client.config;

import java.io.IOException;
import java.time.Clock;
import java.time.Duration;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.ui.Model;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomOauth2AuthenticationFilter extends AbstractAuthenticationProcessingFilter {

	public static final String DEFAULT_FILTER_PROCESSING_URI = "/oauth2Login/**";

	private DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

	private OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository;

	private OAuth2AuthorizationSuccessHandler authorizationSuccessHandler;

	private Duration clockSkew = Duration.ofSeconds(3600);

	private Clock clock = Clock.systemUTC();

	protected CustomOauth2AuthenticationFilter(DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager, OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository ) {
		super(DEFAULT_FILTER_PROCESSING_URI);
		this.auth2AuthorizedClientManager = auth2AuthorizedClientManager;
		this.auth2AuthorizedClientRepository = auth2AuthorizedClientRepository;

		this.authorizationSuccessHandler = (authorizedClient, principal, attributes) -> {this.auth2AuthorizedClientRepository
				.saveAuthorizedClient(authorizedClient, principal,
				(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
				(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));
			log.info("authorizedClient = {}", authorizedClient);
			log.info("principal = {}", principal);
			log.info("attributes = {}", attributes);
		};
		auth2AuthorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException, IOException, ServletException {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if(authentication == null) {
			authentication = new AnonymousAuthenticationToken("anonymous", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
		}

		OAuth2AuthorizeRequest auth2AuthorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("keycloak")
				.principal(authentication)
				.attribute(HttpServletRequest.class.getName(), request)
				.attribute(HttpServletResponse.class.getName(), response)
				.build();

		OAuth2AuthorizedClient auth2AuthorizedClient = auth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);

		if(auth2AuthorizedClient != null) {
			OAuth2UserService<OAuth2UserRequest, OAuth2User> auth2UserService = new DefaultOAuth2UserService();
			ClientRegistration clientRegistration = auth2AuthorizedClient.getClientRegistration();
			OAuth2AccessToken accessToken = auth2AuthorizedClient.getAccessToken();
			OAuth2UserRequest auth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
			OAuth2User auth2User = auth2UserService.loadUser(auth2UserRequest);

			SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
			simpleAuthorityMapper.setPrefix("SYSTEM_");

			OAuth2AuthenticationToken auth2AuthenticationToken = new OAuth2AuthenticationToken(auth2User, auth2User.getAuthorities(), clientRegistration.getRegistrationId());

			this.authorizationSuccessHandler.onAuthorizationSuccess(auth2AuthorizedClient, auth2AuthenticationToken,
					createAttributes(request, response));
			log.info("인증처리!!");
			return authentication;
		}

		//passwordGrantTypeAuthentication(model, auth2AuthorizedClient);

		return authentication;
	}




		private Map<String, Object> createAttributes(HttpServletRequest request, HttpServletResponse response) {
		Map<String, Object> attributes = new HashMap<>();
		attributes.put(HttpServletRequest.class.getName(), request);
		attributes.put(HttpServletResponse.class.getName(), response);
		return attributes;
	}

		private boolean hasTokenExpired(OAuth2AccessToken accessToken) {
			return this.clock.instant().isAfter(accessToken.getExpiresAt().minus(this.clockSkew));
		}


}
