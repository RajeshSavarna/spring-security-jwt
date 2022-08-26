package com.example.springsecurity.filter;

import java.io.IOException;
import java.util.ArrayList;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import com.example.springsecurity.jwt.JwtUtils;
import com.example.springsecurity.service.UserDetailsServiceImpl;

@Component
public class JwtRequestFilter extends OncePerRequestFilter {
	
	@Autowired
	UserDetailsServiceImpl userDetailsService;
	
	@Autowired
	JwtUtils jwtUtils;
	
	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
			throws ServletException, IOException {
		final String authorizationHeader = request.getHeader("Authorization");

		String userName = null;
		String jwt = null;
		
        if (authorizationHeader != null && authorizationHeader.startsWith("Bearer ")) {
        	jwt = authorizationHeader.substring(7);
        	userName = jwtUtils.extractUserName(jwt);
        } 

		if (userName != null/* && SecurityContextHolder.getContext().getAuthentication() == null */) {
        	UserDetails userDetails = this.userDetailsService.loadUserByUsername(userName);
//        	if (jwtUtils.validateToken(jwt, userDetails)) {
        	if (!jwtUtils.isTokenExpired(jwt)) {
        		UsernamePasswordAuthenticationToken usernamePasswordAuthenticationToken = new 
        				UsernamePasswordAuthenticationToken(userDetails, null, new ArrayList<>());
//        		usernamePasswordAuthenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
        		SecurityContextHolder.getContext().setAuthentication(usernamePasswordAuthenticationToken);
        	}
        }
		filterChain.doFilter(request, response);
	}

}
