package com.ideatec.oauth2client.controller;

import java.util.Arrays;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserService;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizedClientRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class ClientController {

	@Autowired
	private OAuth2AuthorizedClientRepository clientRepository;

	@GetMapping("/client")
	public String client(HttpServletRequest request , Model model) {

		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		String clientRegistrationId = "keycloak";

		OAuth2AuthorizedClient auth2AuthorizedClient = clientRepository
				.loadAuthorizedClient(clientRegistrationId, authentication, request);

		OAuth2AccessToken accessToken = auth2AuthorizedClient.getAccessToken();

		OAuth2UserService<OAuth2UserRequest, OAuth2User> oAuth2UserService = new DefaultOAuth2UserService();
		OAuth2User oAuth2User = oAuth2UserService
				.loadUser(new OAuth2UserRequest(auth2AuthorizedClient.getClientRegistration(), accessToken));
		OAuth2AuthenticationToken auth2AuthenticationToken = new OAuth2AuthenticationToken(oAuth2User,Arrays.asList(
				new SimpleGrantedAuthority("ROLE_USER")), auth2AuthorizedClient.getClientRegistration().getRegistrationId());

		SecurityContextHolder.getContext().setAuthentication(auth2AuthenticationToken);

		model.addAttribute("accessToken", accessToken.getTokenValue());
		model.addAttribute("refreshToken",auth2AuthorizedClient.getRefreshToken().getTokenValue());
		model.addAttribute("principalName", oAuth2User.getName());
		model.addAttribute("clientName", auth2AuthorizedClient.getClientRegistration().getClientName());

		return "client";
	}
}
