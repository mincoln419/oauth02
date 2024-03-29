package com.ideatec.oauth2client.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.client.oidc.web.logout.OidcClientInitiatedLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import jakarta.servlet.Filter;

@Configuration
public class Oauth2ClientConfig {

//	@Bean
//	public ClientRegistrationRepository clientRegistrationRepository() {
//		return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
//	}
//
//
//	private ClientRegistration keycloakClientRegistration() {
//
//		return 	ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
//				.registrationId("keycloak1")
//				.scope("openid","profile")
//				.clientId("oauth2-client-app")
//				.clientName("oauth2-client-app")
//				.clientSecret("TjdfuL0uelZKt1GlObMq1V89RKkOJMG3")
//				.redirectUri("http://localhost:20887/client")
//				.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
//				.build();
//	}

	@Autowired
	private DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

	@Autowired
	private OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository;

	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(auth -> auth.requestMatchers("/", "/client", "/oauth2Login","/v2/oauth2Login", "/logoutOuath")
				.permitAll().anyRequest().authenticated());
		// http.oauth2Login(oauth -> oauth.loginPage("/loginPage"));
		// Oauth2Login custom
//		http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
//				.loginProcessingUrl("/login/oauth2/code/*")
//				.authorizationEndpoint(auth -> auth.baseUri("/oauth2/authorization"))
//				.redirectionEndpoint(auth -> auth.baseUri("/login/oauth2/code/*"))
//				);
		// Custom Resolver 사용
		// http.oauth2Login(auth -> auth.authorizationEndpoint(end ->
		// end.authorizationRequestResolver(cutomOAuth2AuthorizationRequestResolver())));
		http.oauth2Client(Customizer.withDefaults());
		http.addFilterBefore(customOauth2AuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);

		return http.build();
	}

	private CustomOauth2AuthenticationFilter customOauth2AuthenticationFilter() {

		CustomOauth2AuthenticationFilter authenticationFilter = new CustomOauth2AuthenticationFilter(
				auth2AuthorizedClientManager, auth2AuthorizedClientRepository);
		authenticationFilter.setAuthenticationSuccessHandler((request, response, authentication) -> {
			response.sendRedirect("/home");
		});

		return authenticationFilter;
	}
}
