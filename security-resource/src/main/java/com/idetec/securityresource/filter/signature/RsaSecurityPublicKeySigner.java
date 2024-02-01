package com.idetec.securityresource.filter.signature;

import java.security.PrivateKey;

import org.springframework.security.core.userdetails.UserDetails;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.RSAKey;

public class RsaSecurityPublicKeySigner extends SecuritySigner{

	private PrivateKey privateKey;

	@Override
	public String getToken(UserDetails user, JWK jwk) {

		try {
			RSASSASigner jwsSigner = new RSASSASigner(privateKey);
			return super.getJwtTokenInterval(jwsSigner, user, jwk);
		} catch (JOSEException e) {
			throw new RuntimeException(e);
		}
	}

	public void setPrivateKey(PrivateKey privateKey) {
		this.privateKey = privateKey;
	}
}
