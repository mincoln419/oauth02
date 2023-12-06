package com.ideatec.securityserver.controller;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.ideatec.securityserver.entity.User;

@RestController
@RequestMapping("/api/")
public class CorsController2 {

	@GetMapping("/users")
	public User users() {
		return new User("user", 20);
	}
}
