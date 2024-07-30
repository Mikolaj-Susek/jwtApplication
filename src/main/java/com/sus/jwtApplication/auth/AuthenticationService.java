package com.sus.jwtApplication.auth;


import com.sus.jwtApplication.config.JwtService;
import com.sus.jwtApplication.user.Role;
import com.sus.jwtApplication.user.User;
import com.sus.jwtApplication.user.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UserDetailsRepositoryReactiveAuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthenticationService {

    private final UserRepository repository;        // because we need to manipulate database

    private final PasswordEncoder passwordEncoder;  //

    private final JwtService jwtService;            //

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
        var user = repository.findUserByEmail(request.getEmail())   // find user details in database by email from response
                .orElseThrow();
        var jwtToken = jwtService.generateToken(user);         // create new token from database user details.

        return AuthenticationResponse.builder()                 // build response object that will carry generated auth token
                .token(jwtToken)
                .build();
    }

}
