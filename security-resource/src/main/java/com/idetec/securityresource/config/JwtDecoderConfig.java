package com.idetec.securityresource.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.jwk.OctetSequenceKey;

@Configuration
public class JwtDecoderConfig {

	@Bean
	@ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name="jws-algorithms", havingValue = "HS256", matchIfMissing = false)
	public JwtDecoder jwtDecoderBySecretKeyValue(OctetSequenceKey octetSequenceKey, OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {

		return NimbusJwtDecoder.withSecretKey(octetSequenceKey.toSecretKey())
				.macAlgorithm(MacAlgorithm.from(oAuth2ResourceServerProperties.getJwt().getJwsAlgorithms().get(0)))
				.build();
	}
}
