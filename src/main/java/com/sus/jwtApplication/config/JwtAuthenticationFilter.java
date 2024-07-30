package com.sus.jwtApplication.config;

import com.sus.jwtApplication.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.CachingUserDetailsService;
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

        if (authHeader == null || !authHeader.startsWith("Bearer ")) { // In token start with this word and space
            filterChain.doFilter(request, response);                  // pass to another filter
            return;
        }

        jwt = authHeader.substring(7);                      // To remove "Bearer " from token

        userEmail = jwtService.extractUsername(jwt);    // todo extract the userEmail from JWT token;
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {          // if user is not authonticated

            UserDetails userDetails = this.userDetailsService.loadUserByUsername(userEmail);                // got user details from database

            if (jwtService.isTokenValid(jwt, userDetails)) {                                                // check if token is valid with user details

                UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(    // create new auth token
                        userDetails,
                        null,
                        userDetails.getAuthorities()
                );
                authToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)          // extend authToken with details of request
                );
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }
        filterChain.doFilter(request, response);

    }
}
