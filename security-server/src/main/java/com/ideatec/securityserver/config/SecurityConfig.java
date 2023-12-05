package com.ideatec.securityserver.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
		http.formLogin(Customizer.withDefaults());
		http.apply(new CustomSecurityConfigure().setFlag(true));
		return http.build();
	}

}
