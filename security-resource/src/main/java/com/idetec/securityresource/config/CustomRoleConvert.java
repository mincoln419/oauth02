package com.idetec.securityresource.config;

import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

public class CustomRoleConvert implements Converter<Jwt, Collection<GrantedAuthority>>{

	private final String PREFIX = "ROLE_";

	@Override
	public Collection<GrantedAuthority> convert(Jwt jwt) {

		String scopes = jwt.getClaimAsString("scope");

		Map<String, Object> realms_access = jwt.getClaimAsMap("realm_access");

		if(scopes == null || realms_access == null) {
			return Collections.emptyList();
		}
		Collection<GrantedAuthority> authorities1 = Arrays.stream(scopes.split(" "))
				.map(roleName -> PREFIX + roleName)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		Collection<GrantedAuthority> authorities2 = ((List<String>)realms_access.get("roles")).stream()
				.map(roleName -> PREFIX + roleName)
				.map(SimpleGrantedAuthority::new)
				.collect(Collectors.toList());

		authorities1.addAll(authorities2);

		return authorities1;
	}

}
