package com.ideatec.oauth2client.service;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

@Service
public class Oauth2Service {

	public String oauthClientParsing() {
		
		OAuth2User oAuth2User = new DefaultOAuth2User(null, null, null);
		
		return "oauth2";
	}
}
