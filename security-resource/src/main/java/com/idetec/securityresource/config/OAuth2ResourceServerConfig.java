package com.idetec.securityresource.config;

import java.security.interfaces.RSAPublicKey;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.idetec.securityresource.filter.authentication.JwtAuthenticationFilter;
import com.idetec.securityresource.filter.authorization.JwtAuthorizationMacFilter;
import com.idetec.securityresource.filter.authorization.JwtAuthorizationRsaFilter;
import com.idetec.securityresource.filter.authorization.JwtAuthorizationRsaPublicKeyFilter;
import com.idetec.securityresource.filter.signature.MacSecuritySigner;
import com.idetec.securityresource.filter.signature.RsaSecurityPublicKeySigner;
import com.idetec.securityresource.filter.signature.RsaSecuritySigner;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

import jakarta.servlet.Filter;

@Configuration
public class OAuth2ResourceServerConfig {

	@Autowired
	private OAuth2ResourceServerProperties auth2ResourceServerProperties;

	@Autowired
	private MacSecuritySigner macSecuritySigner;

	@Autowired
	private RsaSecuritySigner rsaSecuritySigner;

	@Autowired
	private OctetSequenceKey octetSequenceKey;



	@Bean
	public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http.csrf(auth -> auth.disable());
		http.sessionManagement(auth -> auth.sessionCreationPolicy(SessionCreationPolicy.STATELESS));
		http.authorizeHttpRequests(request -> request.requestMatchers("/").permitAll()
				.anyRequest().authenticated());
		//http.oauth2ResourceServer(resource -> resource.jwt(Customizer.withDefaults()));
		http.userDetailsService(userDetailsService());
		//http.addFilterBefore(jwtAuthenticationRSAPublicKeyFilter(null, null), UsernamePasswordAuthenticationFilter.class);
		//http.addFilterBefore(jwtAuthorizationMacFilter(octetSequenceKey), UsernamePasswordAuthenticationFilter.class); //mac filter 적용방식
		//http.addFilterBefore(jwtAuthenticationRsaFilter(null), UsernamePasswordAuthenticationFilter.class);
		//http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		//http.oauth2ResourceServer((oauth2) -> oauth2.jwt(Customizer.withDefaults()));
		//http.addFilterBefore(jwtAuthorizationRsaPublicFilter(null), UsernamePasswordAuthenticationFilter.class);

		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new CustomRoleConvert());
		http.oauth2ResourceServer((oauth2) -> oauth2.jwt(auth -> auth.jwtAuthenticationConverter(jwtAuthenticationConverter)));

		return http.build();
	}

//	@Bean
//	public Filter jwtAuthorizationMacFilter( OctetSequenceKey octetSequenceKey) {
//
//
//		return new JwtAuthorizationMacFilter(octetSequenceKey);
//	}

	@Bean
	public JwtAuthorizationRsaPublicKeyFilter jwtAuthorizationRsaPublicFilter(JwtDecoder jwtDecoder) {
		return new JwtAuthorizationRsaPublicKeyFilter(jwtDecoder);
	}

	@Bean
	public Filter jwtAuthenticationRsaFilter(RSAKey rsaKey) throws Exception {
		return new JwtAuthorizationRsaFilter(new RSASSAVerifier(rsaKey.toRSAPublicKey()));
	}

	@Bean
	public AuthenticationManager authenticationRsaManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}


	@Bean
	public Filter jwtAuthenticationRSAPublicKeyFilter(RsaSecurityPublicKeySigner rsaSecurityPublicKeySigner, RSAKey rsaKey) throws Exception {

		JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(rsaSecurityPublicKeySigner, rsaKey);
		jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
		return jwtAuthenticationFilter;
	}


	@Bean
	public Filter jwtAuthenticationRSAFilter(RsaSecuritySigner securitySigner, RSAKey rsaKey) throws Exception {

		JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(securitySigner, rsaKey);
		jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
		return jwtAuthenticationFilter;
	}

	@Bean
	public Filter jwtAuthenticationMacFilter(MacSecuritySigner securitySigner, OctetSequenceKey octKey) throws Exception {

		JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(securitySigner, octKey);
		jwtAuthenticationFilter.setAuthenticationManager(authenticationManager(null));
		return jwtAuthenticationFilter;
	}


	@Bean
	public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
		return authenticationConfiguration.getAuthenticationManager();
	}

	@Bean
	public UserDetailsService userDetailsService() {
		UserDetails user =  User.withUsername("user").password("1234").authorities("ROLE_USER").build();
		return new InMemoryUserDetailsManager(user);
	}

	@Bean
	public PasswordEncoder passwordEncoder() {
		return NoOpPasswordEncoder.getInstance();
	}

	// @Bean
	public JwtDecoder jwtDecoder1() {
		return JwtDecoders.fromIssuerLocation(auth2ResourceServerProperties.getJwt().getIssuerUri());
	}

	// @Bean
	public JwtDecoder jwtDecoder2() {
		return JwtDecoders.fromOidcIssuerLocation(auth2ResourceServerProperties.getJwt().getIssuerUri());
	}

	//@Bean
	public NimbusJwtDecoder jwtDecoder3() {
		return NimbusJwtDecoder.withJwkSetUri(auth2ResourceServerProperties.getJwt().getJwkSetUri())
				.jwsAlgorithm(SignatureAlgorithm.RS512).build();
	}
}
