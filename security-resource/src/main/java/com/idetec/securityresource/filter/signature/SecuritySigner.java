package com.idetec.securityresource.filter.signature;

import java.time.LocalDateTime;
import java.util.Date;

import org.springframework.security.core.userdetails.UserDetails;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public abstract class SecuritySigner {



	public String getJwtTokenInterval(MACSigner jwsSigner, UserDetails user, JWK jwk) throws JOSEException {
		JWSHeader jweHeader = new JWSHeader.Builder((JWSAlgorithm) jwk.getAlgorithm()).keyID(jwk.getKeyID()).build();
		JWTClaimsSet jwtClaimsSet = new JWTClaimsSet.Builder()
				.subject("user")
				.issuer("http://localhost:28881")
				.claim("username", user.getUsername())
				.claim("authority", user.getAuthorities())
				.expirationTime(new Date(new Date().getTime() + 60 * 1000 * 5))
				.build();

		SignedJWT signedJWT = new SignedJWT(jweHeader, jwtClaimsSet);
		signedJWT.sign(jwsSigner);

		String jwtToken = signedJWT.serialize();

		return jwtToken;
	}

	public abstract String getToken(UserDetails user, JWK jwk);

}
