package com.ideatec.oauth2client.config;

import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.client.OAuth2AuthorizationContext;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProvider;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientProviderBuilder;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.util.StringUtils;

import jakarta.servlet.http.HttpServletRequest;

@Configuration
public class AppConfig {

	@Bean
	public OAuth2AuthorizedClientManager auth2AuthorizedClientManager(
			ClientRegistrationRepository clientRegistrationRepository,
			OAuth2AuthorizedClientRepository oAuth2AuthorizedClientRepository) {

		OAuth2AuthorizedClientProvider auth2AuthorizedClientProvider = OAuth2AuthorizedClientProviderBuilder
				.builder()
				.password()
				.authorizationCode()
				.clientCredentials()
				.refreshToken()
				.build();

		DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager = new DefaultOAuth2AuthorizedClientManager(
				clientRegistrationRepository, oAuth2AuthorizedClientRepository);
		auth2AuthorizedClientManager.setAuthorizedClientProvider(auth2AuthorizedClientProvider);
		auth2AuthorizedClientManager.setContextAttributesMapper(contextAttributesMapper());
		return auth2AuthorizedClientManager;
	}

	private Function<OAuth2AuthorizeRequest, Map<String, Object>> contextAttributesMapper() {

		return oauth2Request -> {
			Map<String, Object> contextAttributes = new HashMap<>();
			HttpServletRequest request =  oauth2Request.getAttribute(HttpServletRequest.class.getName());
			String username = request.getParameter(OAuth2ParameterNames.USERNAME);
			String password = request.getParameter(OAuth2ParameterNames.PASSWORD);

			if(StringUtils.hasText(username) && StringUtils.hasText(password)) {
				contextAttributes.put(OAuth2AuthorizationContext.USERNAME_ATTRIBUTE_NAME, username);
				contextAttributes.put(OAuth2AuthorizationContext.PASSWORD_ATTRIBUTE_NAME, password);
			}
			return contextAttributes;
		};
	}
	
}
