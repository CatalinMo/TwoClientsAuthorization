package com.example.spring.SpringBootOAuthClient2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.security.Principal;

@SpringBootApplication
@RestController
public class SpringBootOAuthClient2Application {

	@GetMapping("/")
	public String securedPage() {
		return "This is client";
	}


	public static void main(String[] args) {
		SpringApplication.run(SpringBootOAuthClient2Application.class, args);
	}
}