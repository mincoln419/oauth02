package com.idetec.securityresource.filter.authorization;

import com.nimbusds.jose.crypto.MACVerifier;

public class JwtAuthorizationMacFilter extends JwtAuthorizationFilter{

	public JwtAuthorizationMacFilter(MACVerifier jwsVerifier) {
		super(jwsVerifier);
	}


}
