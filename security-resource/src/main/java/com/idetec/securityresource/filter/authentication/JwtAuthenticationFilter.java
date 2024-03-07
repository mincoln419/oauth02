package com.idetec.securityresource.filter.authentication;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.idetec.securityresource.dto.LoginDto;
import com.idetec.securityresource.filter.signature.SecuritySigner;
import com.nimbusds.jose.jwk.JWK;



public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter{

	private SecuritySigner securitySigner;
	private JWK jwk;


	public JwtAuthenticationFilter(SecuritySigner signer, JWK jwk) {
		this.securitySigner = signer;
		this.jwk = jwk;
	}

	@Override
	public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
			throws AuthenticationException {

		ObjectMapper objectMapper = new ObjectMapper();
		LoginDto loginDto = null;

		try {
			loginDto = objectMapper.readValue(request.getInputStream(), LoginDto.class);
		} catch (IOException e) {
			throw new RuntimeException();
		}

		UsernamePasswordAuthenticationToken authenticationToken =  new UsernamePasswordAuthenticationToken(loginDto.getUsername(), loginDto.getPassword());

		return getAuthenticationManager().authenticate(authenticationToken);
	}

	@Override
	protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain,
			Authentication authResult) throws IOException, ServletException {


//		SecurityContextHolder.getContext().setAuthentication(authResult);
//		getSuccessHandler().onAuthenticationSuccess(request, response, authResult);

		User user = (User) authResult.getPrincipal();

		String jwtToken = securitySigner.getToken(user, jwk);
		response.addHeader("Authorization", "Bearer " + jwtToken);
	}
}
