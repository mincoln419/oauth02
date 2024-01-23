package com.idetec.securityresource.filter.signature;

import org.springframework.security.core.userdetails.UserDetails;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;

public class MacSecuritySigner extends SecuritySigner{

	@Override
	public String getToken(UserDetails user, JWK jwk) {

		try {
			MACSigner jwsSigner = new MACSigner(((OctetSequenceKey) jwk).toSecretKey());
			return super.getJwtTokenInterval(jwsSigner, user, jwk);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}


}
