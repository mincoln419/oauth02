package com.idetec.securityresource.filter.authorization;

import com.nimbusds.jose.crypto.RSASSAVerifier;

public class JwtAuthorizationRsaFilter extends JwtAuthorizationFilter{

	public JwtAuthorizationRsaFilter(RSASSAVerifier jwsVerifier) {
		super(jwsVerifier);
	}


}
