package com.ideatec.oauth2client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {


	@Autowired
	private OAuth2AuthorizedClientService auth2AuthorizedClientService;

	@GetMapping("/home")
	public String home(Model model, OAuth2AuthenticationToken auth2AuthenticationToken) {

		OAuth2AuthorizedClient auth2AuthorizedClient =  auth2AuthorizedClientService.loadAuthorizedClient("keycloak", auth2AuthenticationToken.getName());
		model.addAttribute("auth2AuthenticationToken", auth2AuthenticationToken);
		model.addAttribute("refreshToken", auth2AuthorizedClient.getRefreshToken().getTokenValue());
		model.addAttribute("acessToken", auth2AuthorizedClient.getAccessToken().getTokenValue());

		return "home";
	}
}
