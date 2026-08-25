package com.zs.spring_security_advanced.controller;

import com.zs.spring_security_advanced.entity.User;
import com.zs.spring_security_advanced.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api")
@RequiredArgsConstructor
public class UserController {

    private final UserRepository userRepository;

    @GetMapping("/me")
    public ResponseEntity<Map<String, Object>> me(@AuthenticationPrincipal User user) {
        return ResponseEntity.ok(Map.of(
                "id", user.getId(),
                "name", user.getName(),
                "email", user.getEmail(),
                "role", user.getRole(),
                "lastLoginAt", user.getLastLoginAt() != null ? user.getLastLoginAt() : "never",
                "failedAttempts", user.getFailedLoginAttempts()));
    }

    @GetMapping("/admin/users")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<User>> listUsers() {
        return ResponseEntity.ok(userRepository.findAll());
    }

    @GetMapping("/admin/locked-accounts")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<Map<String, Object>>> lockedAccounts() {
        List<Map<String, Object>> locked = userRepository.findAll().stream()
                .filter(User::isAccountLocked)
                .map(u -> Map.<String, Object>of(
                        "email", u.getEmail(),
                        "lockedUntil", u.getLockedUntil(),
                        "failedAttempts", u.getFailedLoginAttempts()))
                .toList();
        return ResponseEntity.ok(locked);
    }
}
