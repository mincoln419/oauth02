package com.idetec.securityresource.filter.authorization;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.filter.OncePerRequestFilter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;


public abstract class JwtAuthorizationFilter extends OncePerRequestFilter{

	private JWSVerifier jwkVerifier;

	protected static String PREFIX = "Bearer ";

	public JwtAuthorizationFilter(JWSVerifier jwkVerifier) {
		this.jwkVerifier = jwkVerifier;

	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		if(tokenResolve(request)) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = getToken(request);

		SignedJWT signedJWT;

		try {
			signedJWT = SignedJWT.parse(token);
			boolean verified = signedJWT.verify(jwkVerifier);

			if(verified) {
				JWTClaimsSet claimsSet =  signedJWT.getJWTClaimsSet();
				String username = claimsSet.getClaim("username").toString();
				List<String> authroity = ((List<String>)claimsSet.getClaim("authority"));

				if(username != null) {
					UserDetails user =  User.withUsername(username)
					.password(UUID.randomUUID().toString())
					.authorities(authroity.get(0)).build();

					Authentication authentication = new UsernamePasswordAuthenticationToken(user, null, user.getAuthorities());
					SecurityContextHolder.getContext().setAuthentication(authentication);
				}
			}
		} catch (ParseException | JOSEException e) {
			e.printStackTrace();
			throw new RuntimeException(e);
		}
		filterChain.doFilter(request, response);
	}

	protected String getToken(HttpServletRequest request) {
		return request.getHeader("Authorization").replace(PREFIX, "");
	}

	protected boolean tokenResolve(HttpServletRequest request) {
		String header = request.getHeader("Authorization");
		return header == null || !header.startsWith(PREFIX);
	}

}
