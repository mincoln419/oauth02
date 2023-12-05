package com.ideatec.securityserver.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;

import lombok.extern.slf4j.Slf4j;

@Slf4j
public class CustomSecurityConfigure extends AbstractHttpConfigurer<CustomSecurityConfigure,HttpSecurity> {


	private boolean isSecure;

	@Override
	public void init(HttpSecurity builder) throws Exception {
		log.info("init method starting...");
		super.init(builder);
	}

	@Override
	public void configure(HttpSecurity builder) throws Exception {

		log.info("configure method starting...");
		super.configure(builder);
		if(isSecure) {
			log.info("http is required");
		}else {
			log.info("http is optional");
		}
	}

	public CustomSecurityConfigure setFlag(boolean isSecure) {
		this.isSecure = isSecure;
		return this;
	}
}
