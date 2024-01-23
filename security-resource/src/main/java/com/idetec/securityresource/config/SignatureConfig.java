package com.idetec.securityresource.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.idetec.securityresource.filter.signature.MacSecuritySigner;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.gen.OctetSequenceKeyGenerator;

@Configuration
public class SignatureConfig {

	@Bean
	public MacSecuritySigner macSecuritySigner() {
		return new MacSecuritySigner();
	}


	@Bean
	public OctetSequenceKey octetSequenceKey() throws JOSEException {

		OctetSequenceKey octetSequenceKey = new OctetSequenceKeyGenerator(256)
				.keyID("macKey")
				.algorithm(JWSAlgorithm.HS256)
				.generate();
		return octetSequenceKey;

	}
}
