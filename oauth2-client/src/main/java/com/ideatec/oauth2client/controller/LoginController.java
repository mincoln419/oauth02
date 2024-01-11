package com.ideatec.oauth2client.controller;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Controller
public class LoginController {

	@GetMapping("/oauth2Login")
	public String oauth2Login(Model model, HttpServletRequest request, HttpServletResponse response ) {


		return "redirect:/";
	}

	@GetMapping("/logout")
	public String logout(Authentication authentication, HttpServletResponse response, HttpServletRequest request) {

		SecurityContextLogoutHandler logoutHandler = new SecurityContextLogoutHandler();
		logoutHandler.logout(request, response, authentication);
		return "redirect:/";
	}
}
