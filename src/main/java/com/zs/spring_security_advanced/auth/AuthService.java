package com.zs.spring_security_advanced.auth;

import com.zs.spring_security_advanced.dto.AuthResponse;
import com.zs.spring_security_advanced.dto.LoginRequest;
import com.zs.spring_security_advanced.dto.RegisterRequest;
import com.zs.spring_security_advanced.entity.Role;
import com.zs.spring_security_advanced.entity.SecurityEvent;
import com.zs.spring_security_advanced.entity.User;
import com.zs.spring_security_advanced.jwt.JwtService;
import com.zs.spring_security_advanced.repository.SecurityEventRepository;
import com.zs.spring_security_advanced.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import java.time.LocalDateTime;

@Slf4j
@Service
@RequiredArgsConstructor
public class AuthService {

    private final UserRepository userRepository;
    private final SecurityEventRepository eventRepository;
    private final JwtService jwtService;
    private final PasswordEncoder passwordEncoder;

    @Value("${app.security.max-login-attempts}")
    private int maxAttempts;

    @Value("${app.security.lockout-duration-minutes}")
    private int lockoutMinutes;

    public AuthResponse register(RegisterRequest request) {
        if (userRepository.existsByEmail(request.email())) {
            throw new IllegalArgumentException("Email already registered: " + request.email());
        }

        User user = User.builder()
                .name(request.name())
                .email(request.email())
                .password(passwordEncoder.encode(request.password()))
                .role(Role.ROLE_USER)
                .build();

        userRepository.save(user);
        log.info("User registered: {}", user.getEmail());

        String access = jwtService.generateToken(user);
        String refresh = jwtService.generateRefreshToken(user);
        return AuthResponse.of(access, refresh, user.getEmail(), user.getRole().name());
    }

    public AuthResponse login(LoginRequest request, String ipAddress) {
        User user = userRepository.findByEmail(request.email())
                .orElseThrow(() -> new BadCredentialsException("Invalid credentials"));

        // Verifica se a conta está bloqueada
        if (user.isAccountLocked()) {
            logEvent(user.getEmail(), "LOGIN_BLOCKED", ipAddress,
                    "Account locked until " + user.getLockedUntil());
            throw new LockedException("Account locked until " + user.getLockedUntil());
        }

        // Valida a senha
        if (!passwordEncoder.matches(request.password(), user.getPassword())) {
            handleFailedLogin(user, ipAddress);
            throw new BadCredentialsException("Invalid credentials");
        }

        // Login bem sucedido — reseta tentativas
        user.setFailedLoginAttempts(0);
        user.setLockedUntil(null);
        user.setLastLoginAt(LocalDateTime.now());
        userRepository.save(user);

        logEvent(user.getEmail(), "LOGIN_SUCCESS", ipAddress, "Login successful");
        log.info("User logged in: {}", user.getEmail());

        String access = jwtService.generateToken(user);
        String refresh = jwtService.generateRefreshToken(user);
        return AuthResponse.of(access, refresh, user.getEmail(), user.getRole().name());
    }

    public String logout(String token) {
        String email = jwtService.extractUsername(token);
        jwtService.blacklistToken(token);
        logEvent(email, "LOGOUT", "N/A", "Token blacklisted");
        log.info("User logged out: {}", email);
        return email;
    }

    private void handleFailedLogin(User user, String ipAddress) {
        int attempts = user.getFailedLoginAttempts() + 1;
        user.setFailedLoginAttempts(attempts);

        if (attempts >= maxAttempts) {
            user.setLockedUntil(LocalDateTime.now().plusMinutes(lockoutMinutes));
            userRepository.save(user);
            logEvent(user.getEmail(), "ACCOUNT_LOCKED", ipAddress,
                    "Locked after " + attempts + " failed attempts");
            log.warn("Account locked: {} after {} failed attempts", user.getEmail(), attempts);
        } else {
            userRepository.save(user);
            logEvent(user.getEmail(), "LOGIN_FAILED", ipAddress,
                    "Attempt " + attempts + " of " + maxAttempts);
            log.warn("Failed login for: {} — attempt {}/{}", user.getEmail(), attempts, maxAttempts);
        }
    }

    private void logEvent(String email, String type, String ip, String details) {
        eventRepository.save(SecurityEvent.builder()
                .email(email)
                .eventType(type)
                .ipAddress(ip)
                .details(details)
                .build());
    }
}
