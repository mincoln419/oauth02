package com.idetec.securityresource.config;

import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.security.oauth2.jose.jws.MacAlgorithm;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;

@Configuration
public class JwtDecoderConfig {

	@Bean
	@ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name="jws-algorithms", havingValue = "HS256", matchIfMissing = false)
	public JwtDecoder jwtDecoderBySecretKeyValue(OctetSequenceKey octetSequenceKey, OAuth2ResourceServerProperties oAuth2ResourceServerProperties) {

		return NimbusJwtDecoder.withSecretKey(octetSequenceKey.toSecretKey())
				.macAlgorithm(MacAlgorithm.from(oAuth2ResourceServerProperties.getJwt().getJwsAlgorithms().get(0)))
				.build();
	}

	@Bean
	@Primary
	@ConditionalOnProperty(prefix = "spring.security.oauth2.resourceserver.jwt", name="jws-algorithms", havingValue = "RS512", matchIfMissing = false)
	public JwtDecoder jwtDecoderByPublicKeyValue(RSAKey rsakey, OAuth2ResourceServerProperties oAuth2ResourceServerProperties) throws JOSEException {

		return NimbusJwtDecoder.withPublicKey(rsakey.toRSAPublicKey())
				.signatureAlgorithm(SignatureAlgorithm.from(oAuth2ResourceServerProperties.getJwt().getJwsAlgorithms().get(0)))
				.build();
	}// application yml 과 일치된 것이 없으면 JWTDecoder는 기본 JWT Decoder 객체로 만들어서 세팅함 -> application yml 
}
