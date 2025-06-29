package com.application.auth.authen.config;

import com.application.auth.authen.dto.AuthRequestDTO;
import com.application.auth.authen.dto.AuthResponseDTO;
import com.application.auth.authen.dto.RegisterRequestDTO;
import com.application.auth.authen.entity.User;
import com.application.auth.authen.entity.UserDetailsImpl;
import com.application.auth.authen.repository.UserRepository;
import com.application.auth.authen.service.JwtService;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
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
                .role(request.getRole())
                .build();
        var userDetails = new UserDetailsImpl(user);

        userRepository.save(user);
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);
        var userDto = User.builder()
                .id(user.getId())
                .username(user.getUsername())
                .role(user.getRole())
                .email(user.getEmail())
                .build();
        return new AuthResponseDTO(accessToken, refreshToken, "Bearer", userDto, "User registered successfully");
    }

    public AuthResponseDTO authenticate(AuthRequestDTO request) {
        authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(request.getUsername(), request.getPassword()));

        var user = userRepository.findByUsername(request.getUsername()).orElseThrow();
        var userDetails = new UserDetailsImpl(user);
        String accessToken = jwtService.generateAccessToken(userDetails);
        String refreshToken = jwtService.generateRefreshToken(userDetails);
        var userDto = User.builder()
                .id(user.getId())
                .username(user.getUsername())
                .role(user.getRole())
                .email(user.getEmail())
                .build();
        return new AuthResponseDTO(accessToken, refreshToken, "Bearer", userDto, "User login successfully");
    }

}
