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
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

@Configuration
public class Oauth2ClientConfig {

	//@Bean
	public ClientRegistrationRepository clientRegistrationRepository() {
		return new InMemoryClientRegistrationRepository(keycloakClientRegistration());
	}

	@Autowired
	ClientRegistrationRepository clientRegistrationRepository;

	private ClientRegistration keycloakClientRegistration() {

		return 	ClientRegistrations.fromIssuerLocation("http://localhost:8080/realms/oauth2")
				.registrationId("keycloak")
				.scope("profile email")
				.clientId("oauth2-client-app")
				.clientName("oauth2-client-app")
				.clientSecret("WOK6puaB91PpJFuFonHke8hbE2oYoilG")
				.redirectUri("http://localhost:20887/login/oauth2/code/keycloak")
				.build();
	}


	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception{

		http.authorizeHttpRequests(auth -> auth.requestMatchers("/login").permitAll()
				.anyRequest().authenticated());
		//http.oauth2Login(oauth -> oauth.loginPage("/loginPage"));
		http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
				.loginProcessingUrl("/login/v1/oauth2/code/*")
				.authorizationEndpoint(auth -> auth.baseUri("/oauth2/v1/authorization"))
				.redirectionEndpoint(auth -> auth.baseUri("/login/v1/oauth2/code/*"))
				);
		http.logout(auth -> auth.logoutSuccessHandler(oidcLogoutSuccessHandler())
				.invalidateHttpSession(true)
				.clearAuthentication(true)
				.deleteCookies("JSESSIONID")
				);
		return http.build();
	}

	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		successHandler.setPostLogoutRedirectUri("http://localhost:20887/login");
		return successHandler;
	}
}
