package com.ideatec.oauth2client.controller;

import java.util.HashMap;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.Getter;

@Component
public class GroupBinding {

	@Autowired
	HomeController jpaRepository;

	@Bean
	public Map<String, ClientVo> getClientVo() {

		Map<String, ClientVo> map = new HashMap<>();

		map.put("admin", ClientVo.builder().clientId("").clientSecret("").build());
		map.put("normal", ClientVo.builder().clientId("").clientSecret("").build());

		return map;
	}

}

@Data
@AllArgsConstructor
@Builder
class ClientVo {

	private String clientId;
	private String clientSecret;

}

class Test{

	@Autowired
	private  Map<String, ClientVo> testMap;


	public void test() {
		testMap.get("admin");

		if(GroupIds.valueOf("") == GroupIds.ADMIN) {
			testMap.get("admin").getClientId();
			testMap.get("admin").getClientSecret();
		}

	}

}