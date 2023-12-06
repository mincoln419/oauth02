package com.ideatec.securityserver.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class CorsController {

	@GetMapping("/home")
	public String index() {
		return "index";
	}
}
