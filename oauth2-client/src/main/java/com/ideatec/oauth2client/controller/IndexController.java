package com.ideatec.oauth2client.controller;

import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.IdTokenClaimNames;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class IndexController {

	@Autowired
	private ClientRegistrationRepository clientRegistrationRepository;



	@GetMapping("/")
	public String index() {
		//ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

		//log.info("client id : {}", clientRegistration.getClientId());

		//log.info("redirect uri : {}", clientRegistration.getRedirectUri());
		return "index";
	}

	@GetMapping("/loginPage")
	public String loginPage() {
		return "loginPage";
	}

	@GetMapping("/user")
	public OAuth2User user(String accessToken) {

		ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
		OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);
		OAuth2UserRequest auth2UserRequest = new OAuth2UserRequest(clientRegistration, auth2AccessToken);
		DefaultOAuth2UserService defaultOAuth2UserService = new DefaultOAuth2UserService();

		OAuth2User auth2User = defaultOAuth2UserService.loadUser(auth2UserRequest);
		return auth2User;
	}


	@GetMapping("/oidc")
	public OAuth2User oidc(String accessToken, String idToken) {

		ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");
		OAuth2AccessToken auth2AccessToken = new OAuth2AccessToken(OAuth2AccessToken.TokenType.BEARER, accessToken, Instant.now(), Instant.MAX);

		Map<String, Object> idTokenClaims = new HashMap<>();
		idTokenClaims.put(IdTokenClaimNames.ISS, "http://localhost:8080/realms/oauth2");
		idTokenClaims.put(IdTokenClaimNames.SUB, "7db36079-9d53-44e9-b7c2-3471e92d64c4");
		idTokenClaims.put("preferred_username", "user");
		OidcIdToken oidcIdToken = new OidcIdToken (idToken, Instant.now(), Instant.MAX, idTokenClaims);
		OidcUserRequest oidcUserRequest = new OidcUserRequest(clientRegistration, auth2AccessToken, oidcIdToken);
		OidcUserService oidcUserService = new OidcUserService();

		OAuth2User auth2User = oidcUserService.loadUser(oidcUserRequest);
		return auth2User;
	}
}
