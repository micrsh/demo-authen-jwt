package com.application.auth.authen.service;

import com.application.auth.authen.dto.AuthRequestDTO;
import com.application.auth.authen.dto.AuthResponseDTO;
import com.application.auth.authen.dto.RegisterRequestDTO;
import com.application.auth.authen.entity.User;
import com.application.auth.authen.entity.UserDetailsImpl;
import com.application.auth.authen.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;
    private final JwtService jwtService;
    private final AuthenticationManager authenticationManager;

    public AuthResponseDTO register(RegisterRequestDTO request) {
        var user = User.builder()
                .username(request.getUsername())
                .password(passwordEncoder.encode(request.getPassword()))
                .build();
        var userDetails = new UserDetailsImpl(user);

        userRepository.save(user);
        String token = jwtService.generateToken(userDetails);
        return new AuthResponseDTO(token);
    }

    public AuthResponseDTO authenticate(AuthRequestDTO request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        var user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        var userDetails = new UserDetailsImpl(user);
        String token = jwtService.generateToken(userDetails);
        return new AuthResponseDTO(token);
    }

}
