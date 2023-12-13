package com.ideatec.oauth2client.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.extern.slf4j.Slf4j;

@RestController
@Slf4j
public class IndexController {

	//@Autowired
	//private ClientRegistrationRepository clientRegistrationRepository;

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
}
