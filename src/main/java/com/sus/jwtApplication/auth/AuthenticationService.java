package com.sus.jwtApplication.auth;

import com.sus.jwtApplication.config.JwtService;
import com.sus.jwtApplication.user.Role;
import com.sus.jwtApplication.user.User;
import com.sus.jwtApplication.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    // Repository to perform database operations on User entities
    private final UserRepository repository;

    // Encoder to hash passwords before saving them
    private final PasswordEncoder passwordEncoder;

    // Service to generate and validate JWT tokens
    private final JwtService jwtService;

    // Manager to authenticate user credentials
    private final AuthenticationManager authenticationManager;

    public AuthenticationResponse register(RegisterRequest request) {
        var user = User.builder()
                .firstname(request.getFirstname())
                .lastname(request.getLastname())
                .email(request.getEmail())
                .password(passwordEncoder.encode(request.getPassword()))
                .role(Role.USER)
                .build();
        repository.save(user);
        var jwtToken = jwtService.generateToken(user);
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
        authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(
                        request.getEmail(),
                        request.getPassword()
                )
        );
        // Retrieve user details from the database using the email from the request
        var user = repository.findUserByEmail(request.getEmail())
                .orElseThrow();
        // Generate a new JWT token based on the user details
        var jwtToken = jwtService.generateToken(user);

        // Build and return the response object containing the generated authentication token
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
