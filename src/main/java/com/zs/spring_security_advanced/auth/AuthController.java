package com.zs.spring_security_advanced.auth;

import com.zs.spring_security_advanced.dto.AuthResponse;
import com.zs.spring_security_advanced.dto.LoginRequest;
import com.zs.spring_security_advanced.dto.RegisterRequest;
import com.zs.spring_security_advanced.entity.User;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/auth")
@RequiredArgsConstructor
public class AuthController {

    private final AuthService authService;

    @PostMapping("/register")
    public ResponseEntity<AuthResponse> register(@RequestBody RegisterRequest request) {
        return ResponseEntity.status(HttpStatus.CREATED).body(authService.register(request));
    }

    @PostMapping("/login")
    public ResponseEntity<AuthResponse> login(
            @RequestBody LoginRequest request,
            HttpServletRequest httpRequest) {
        return ResponseEntity.ok(authService.login(request, httpRequest.getRemoteAddr()));
    }

    @PostMapping("/logout")
    public ResponseEntity<Map<String, String>> logout(
            @RequestHeader("Authorization") String authHeader,
            @AuthenticationPrincipal User user) {
        String token = authHeader.substring(7);
        authService.logout(token, user.getEmail());
        return ResponseEntity.ok(Map.of("message", "Logged out successfully"));
    }
}
