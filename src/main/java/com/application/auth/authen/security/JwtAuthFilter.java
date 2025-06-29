package com.application.auth.authen.security;

import com.application.auth.authen.entity.User;
import com.application.auth.authen.entity.UserDetailsImpl;
import com.application.auth.authen.repository.UserRepository;
import com.application.auth.authen.service.JwtService;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.security.SignatureException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final UserRepository userRepository;


    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        try {
            final String authHeader = request.getHeader("Authorization");
            final String authRequestMatcher = request.getRequestURI();
            final String token;
            final String username;

            if (authHeader == null || !authHeader.startsWith("Bearer ") || authRequestMatcher.contains("/api/auth/login")) {
                filterChain.doFilter(request, response);
                return;
            }

            token = authHeader.substring(7);
            username = jwtService.extractUsername(token);

            if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
                User user = userRepository.findByUsername(username).orElse(null);

                if (user != null) {
                    var userDetails = new UserDetailsImpl(user);

                    if (jwtService.isTokenValid(token, userDetails)) {
                        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                        authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                        SecurityContextHolder.getContext().setAuthentication(authToken);
                    }
                }
            }

            filterChain.doFilter(request, response);
        } catch (ExpiredJwtException ex) {
            throw new RuntimeException("Token đã hết hạn", ex);
        } catch (MalformedJwtException | SignatureException ex) {
            throw new RuntimeException("Token không hợp lệ", ex);
        } catch (Exception ex) {
            throw new RuntimeException("Lỗi xác thực token", ex);
        }
    }
}
