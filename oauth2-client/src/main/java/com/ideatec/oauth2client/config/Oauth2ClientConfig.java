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
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
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
				.requestMatchers("/", "/home","oauth2Login", "/client","/logout").permitAll()
				.anyRequest().authenticated());
		//http.oauth2Login(oauth -> oauth.loginPage("/loginPage"));
		//Oauth2Login custom
//		http.oauth2Login(oauth2 -> oauth2.loginPage("/login")
//				.loginProcessingUrl("/login/oauth2/code/*")
//				.authorizationEndpoint(auth -> auth.baseUri("/oauth2/authorization"))
//				.redirectionEndpoint(auth -> auth.baseUri("/login/oauth2/code/*"))
//				);
		//Custom Resolver 사용
		//http.oauth2Login(auth -> auth.authorizationEndpoint(end -> end.authorizationRequestResolver(cutomOAuth2AuthorizationRequestResolver())));
		http.oauth2Client(Customizer.withDefaults());

//		http.logout(auth -> auth.logoutSuccessHandler(oidcLogoutSuccessHandler())
//				.invalidateHttpSession(true)
//				.clearAuthentication(true)
//				.deleteCookies("JSESSIONID")
//				);
		http.logout(auth-> auth
				.invalidateHttpSession(true)
				.deleteCookies("JESSIONID")
				.clearAuthentication(true)
				.logoutUrl("/home"));
		return http.build();
	}

	private OAuth2AuthorizationRequestResolver cutomOAuth2AuthorizationRequestResolver() {
		return new CustomOAuth2AuthorizationRequestResolver(clientRegistrationRepository, "/oauth2/authorization");
	}


	private LogoutSuccessHandler oidcLogoutSuccessHandler() {
		OidcClientInitiatedLogoutSuccessHandler successHandler = new OidcClientInitiatedLogoutSuccessHandler(clientRegistrationRepository);
		successHandler.setPostLogoutRedirectUri("http://localhost:20887/login");
		return successHandler;
	}
}
