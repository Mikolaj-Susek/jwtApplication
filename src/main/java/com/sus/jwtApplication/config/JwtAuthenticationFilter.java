package com.sus.jwtApplication.config;

import com.sus.jwtApplication.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthenticationFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    @Override
    protected void doFilterInternal(
            @NonNull HttpServletRequest request,
            // we can get data from request
            @NonNull HttpServletResponse response,
            // then we can provide response with new data
            @NonNull FilterChain filterChain
            // Chain of responsibility design pattern (Call next filter in the chain)
    ) throws ServletException, IOException {

        final String authHeader = request.getHeader("Authorization");
        final String jwt;
        final String userEmail;

        // If the Authorization header is missing or does not start with "Bearer ", skip this filter
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }

        // Extract the JWT token from the Authorization header
        jwt = authHeader.substring(7);

        // Extract the user email from the JWT token
        userEmail = jwtService.extractUsername(jwt);

        // If userEmail is not null and there is no current authentication, proceed with validation
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {

            // Load user details from the database using the extracted email
            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);

            // Validate the token against the user details
            if (jwtService.isTokenValid(jwt, userDetails)) {

                // Create an authentication token for the user
                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );

                // Set additional details on the authentication token
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Set the authentication in the security context
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        // Proceed to the next filter in the chain
        filterChain.doFilter(request, response);
    }
}
