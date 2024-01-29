package com.idetec.securityresource.filter.signature;

import org.springframework.security.core.userdetails.UserDetails;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;

public class RsaSecuritySigner extends SecuritySigner{

	@Override
	public String getToken(UserDetails user, JWK jwk) {

		try {
			RSASSASigner jwsSigner = new RSASSASigner(((com.nimbusds.jose.jwk.RSAKey) jwk).toRSAPrivateKey());
			return super.getJwtTokenInterval(jwsSigner, user, jwk);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

}
