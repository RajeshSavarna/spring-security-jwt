package com.example.springsecurity.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

import com.example.springsecurity.jwt.JwtUtils;
import com.example.springsecurity.model.AuthenticateRequest;
import com.example.springsecurity.service.UserDetailsServiceImpl;

@RestController 
public class Controller {
	
	@Autowired
	AuthenticationManager authenticationManager;
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	JwtUtils jwtUtils;
	
	@GetMapping("/hello") 
	public String hello() { 
		return "hello"; 
	} 
	
	@PostMapping("/authenticate") 
	public String authenticate(@RequestBody AuthenticateRequest req) throws Exception { 
		try {
			authenticationManager.authenticate(
				new UsernamePasswordAuthenticationToken(req.getEmail(), req.getPassword())
			);
			
			final UserDetails userDetails = userDetailsService.loadUserByUsername(req.getEmail());
			
			return jwtUtils.generateToken(userDetails);
			
		} catch (BadCredentialsException ex) {
			throw new Exception("Incorrect Username or Password", ex);
		} catch (Exception ex) {
			throw new Exception("Internal Server Error", ex);
		}
	} 
	
}