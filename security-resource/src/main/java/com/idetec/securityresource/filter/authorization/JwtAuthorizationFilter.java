package com.idetec.securityresource.filter.authorization;

import java.io.IOException;
import java.text.ParseException;
import java.util.List;
import java.util.UUID;

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

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public abstract class JwtAuthorizationFilter extends OncePerRequestFilter{

	private JWSVerifier jwkVerifier;

	private static String PREFIX = "Bearer ";

	public JwtAuthorizationFilter(JWSVerifier jwkVerifier) {
		this.jwkVerifier = jwkVerifier;

	}

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {

		String header = request.getHeader("Authorization");

		if(header == null || !header.startsWith(PREFIX)) {
			filterChain.doFilter(request, response);
			return;
		}

		String token = header.replace(PREFIX, "");

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

}
