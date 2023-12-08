package com.ideatec.securityserver.config;

import java.io.IOException;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

@Configuration
@Slf4j
public class SecurityConfig {

	@Bean
	@Order(0)
	SecurityFilterChain securityFilterChain1(HttpSecurity http) throws Exception {

		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
		//http.formLogin(Customizer.withDefaults());
//		http.apply(new CustomSecurityConfigure().setFlag(true));
		http.exceptionHandling(authorize -> authorize.authenticationEntryPoint(new AuthenticationEntryPoint() {

			@Override
			public void commence(HttpServletRequest request, HttpServletResponse response,
					AuthenticationException authException) throws IOException, ServletException {
				log.info("custom entry point");
			}
		}));
		return http.build();
	}

//	@Bean
//	@Order(1)
//	SecurityFilterChain securityFilterChain2(HttpSecurity http) throws Exception {
//
//		http.authorizeHttpRequests(authorize -> authorize.anyRequest().authenticated());
//		http.formLogin(Customizer.withDefaults());
//		http.httpBasic(Customizer.withDefaults());
//		http.apply(new CustomSecurityConfigure().setFlag(true));
//		http.cors(auth -> auth.configurationSource(corsConfigurationSource()));
//		return http.build();
//	}

	@Bean
	public CorsConfigurationSource corsConfigurationSource() {

		CorsConfiguration configuration = new CorsConfiguration();
		configuration.addAllowedOrigin("*");
		configuration.addAllowedMethod("*");
		configuration.addAllowedHeader("*");
		configuration.setAllowCredentials(true);
		configuration.setMaxAge(3600L);
		UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
		source.registerCorsConfiguration("/**", configuration);
		return source;
	}

}
