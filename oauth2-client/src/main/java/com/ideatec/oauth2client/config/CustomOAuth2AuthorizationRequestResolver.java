package com.ideatec.oauth2client.config;

import java.util.function.Consumer;

import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestCustomizers;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import jakarta.servlet.http.HttpServletRequest;

public class CustomOAuth2AuthorizationRequestResolver implements OAuth2AuthorizationRequestResolver{

	private ClientRegistrationRepository clientRegistrationRepository;

	private String baseUri;

	private DefaultOAuth2AuthorizationRequestResolver defaultResolver;

	private final AntPathRequestMatcher authorizationRequestMatcher;

	private static final String REGISTRATION_ID_URI_VARIABLE_NAME = "registrationId";

	private static final Consumer<OAuth2AuthorizationRequest.Builder> DEFAULT_PKCE_APPLIER = OAuth2AuthorizationRequestCustomizers
			.withPkce();

	public CustomOAuth2AuthorizationRequestResolver(ClientRegistrationRepository clientRegistrationRepository, String baseUri) {
		this.clientRegistrationRepository = clientRegistrationRepository;
		this.authorizationRequestMatcher = new AntPathRequestMatcher(
				baseUri + "/{" + REGISTRATION_ID_URI_VARIABLE_NAME + "}");
		this.baseUri = baseUri;

		defaultResolver = new DefaultOAuth2AuthorizationRequestResolver(clientRegistrationRepository, baseUri);
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request) {
		String registrationId = resolveRegistrationId(request);
		if (registrationId == null) {
			return null;
		}

		if (registrationId.equals("keycloakWithPKCE")) {
			OAuth2AuthorizationRequest authorizationRequest = defaultResolver.resolve(request);
			return customResolve(authorizationRequest, registrationId);
		}

		return defaultResolver.resolve(request);
	}

	private OAuth2AuthorizationRequest customResolve(OAuth2AuthorizationRequest authorizationRequest, String registrationId) {
		OAuth2AuthorizationRequest.Builder builder = OAuth2AuthorizationRequest.from(authorizationRequest);
		DEFAULT_PKCE_APPLIER.accept(builder);
		return builder.build();
	}

	@Override
	public OAuth2AuthorizationRequest resolve(HttpServletRequest request, String clientRegistrationId) {
		return null;
	}


	private String resolveRegistrationId(HttpServletRequest request) {
		if (this.authorizationRequestMatcher.matches(request)) {
			return this.authorizationRequestMatcher.matcher(request)
				.getVariables()
				.get(REGISTRATION_ID_URI_VARIABLE_NAME);
		}
		return null;
	}

}
