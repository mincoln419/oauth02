package com.ideatec.oauth2client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.mapping.SimpleAuthorityMapper;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizationSuccessHandler;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.DefaultOAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

	@Autowired
	private DefaultOAuth2AuthorizedClientManager auth2AuthorizedClientManager;

	@Autowired
	private OAuth2AuthorizedClientRepository auth2AuthorizedClientRepository;



		@GetMapping("/oauth2Login")
	public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response ) {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		OAuth2AuthorizeRequest auth2AuthorizeRequest = OAuth2AuthorizeRequest
				.withClientRegistrationId("keycloak")
				.principal(authentication)
				.attribute(HttpServletRequest.class.getName(), request)
				.attribute(HttpServletResponse.class.getName(), response)
				.build();

		OAuth2AuthorizationSuccessHandler authorizationSuccessHandler = (authorizedClient, principal, attributes) -> auth2AuthorizedClientRepository
				.saveAuthorizedClient(authorizedClient, principal,
						(HttpServletRequest) attributes.get(HttpServletRequest.class.getName()),
						(HttpServletResponse) attributes.get(HttpServletResponse.class.getName()));

		auth2AuthorizedClientManager.setAuthorizationSuccessHandler(authorizationSuccessHandler);

		OAuth2AuthorizedClient auth2AuthorizedClient = auth2AuthorizedClientManager.authorize(auth2AuthorizeRequest);

		//passwordGrantTypeAuthentication(model, auth2AuthorizedClient);
		credentialGrantTypeAuthentication(model, auth2AuthorizedClient);

		return "home";
	}

		private void credentialGrantTypeAuthentication(Model model, OAuth2AuthorizedClient auth2AuthorizedClient) {
			model.addAttribute("authorizedClient", auth2AuthorizedClient.getAccessToken().getTokenValue());

		}

		private void passwordGrantTypeAuthentication(Model model, OAuth2AuthorizedClient auth2AuthorizedClient) {
			if(auth2AuthorizedClient != null) {
				OAuth2UserService<OAuth2UserRequest, OAuth2User> auth2UserService = new DefaultOAuth2UserService();
				ClientRegistration clientRegistration = auth2AuthorizedClient.getClientRegistration();
				OAuth2AccessToken accessToken = auth2AuthorizedClient.getAccessToken();
				OAuth2UserRequest auth2UserRequest = new OAuth2UserRequest(clientRegistration, accessToken);
				OAuth2User auth2User = auth2UserService.loadUser(auth2UserRequest);

				SimpleAuthorityMapper simpleAuthorityMapper = new SimpleAuthorityMapper();
				simpleAuthorityMapper.setPrefix("SYSTEMSCOPE_email");

				OAuth2AuthenticationToken auth2AuthenticationToken = new OAuth2AuthenticationToken(auth2User, auth2User.getAuthorities(), clientRegistration.getRegistrationId());

				model.addAttribute("auth2AuthenticationToken",auth2AuthenticationToken);

				System.out.println("인증처리!!");
			}
		}

	@GetMapping("/logoutOuath")
	public String logout(Authentication authentication, HttpServletResponse response, HttpServletRequest request) {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
		return "redirect:/";
	}


	@GetMapping("/")
	public String index() {
		//ClientRegistration clientRegistration = clientRegistrationRepository.findByRegistrationId("keycloak");

		//log.info("client id : {}", clientRegistration.getClientId());

		//log.info("redirect uri : {}", clientRegistration.getRedirectUri());
		return "index";
	}

}
