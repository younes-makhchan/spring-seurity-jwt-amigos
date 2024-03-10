package com.example.springsecurityjwt.auth;

import com.example.springsecurityjwt.entities.Role;
import com.example.springsecurityjwt.entities.User;
import com.example.springsecurityjwt.repositories.UserRepository;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import com.example.springsecurityjwt.config.JwtService;

@Service
@RequiredArgsConstructor
public class AuthenticationService {
    private  final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final AuthenticationManager authenticationManager;
    private final JwtService jwtService;
    public AuthenticationResponse register(RegisterRequest request) {
         var user= User.builder()
                 .firstname(request.getFirstname())
                 .lastname(request.getLastname())
                 .email(request.getEmail())
                 .password(passwordEncoder.encode(request.getPassword()))
                 .role(Role.USER)
                 .build();
         userRepository.save(user);
         var jwtToken=jwtService.generateToken(user);
         //give hhim the token and direct him inside
         return AuthenticationResponse.builder()
                 .token(jwtToken)
                 .build();


    }

    public AuthenticationResponse authenticate(AuthenticationRequest request) {
      authenticationManager.authenticate(
              new UsernamePasswordAuthenticationToken(request.getEmail(),request.getPassword())
      );
      var user=userRepository.findByEmail(request.getEmail()).orElseThrow(()-> new UsernameNotFoundException("not found User"));
        var jwtToken=jwtService.generateToken(user);
        //give hhim the token and direct him inside
        return AuthenticationResponse.builder()
                .token(jwtToken)
                .build();
    }
}
