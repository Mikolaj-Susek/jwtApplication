package com.sus.jwtApplication.config;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,     // we can get data from request
            @NonNull HttpServletResponse response,   // then we can provide response with new data
            @NonNull FilterChain filterChain         // Chain of responsibility design pattern (Call next filter in the chain)
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        if(authHeader == null || !authHeader.startsWith("Bearer ")) { // In token start with this word and space
            filterChain.doFilter(request, response);                  // pass to another filter
            return;
        }

        jwt = authHeader.substring(7);                      // Because to remove "Bearer "

        userEmail = jwtService.extractUsername(); // todo extract the userEmail from JWT token;
    }
}
