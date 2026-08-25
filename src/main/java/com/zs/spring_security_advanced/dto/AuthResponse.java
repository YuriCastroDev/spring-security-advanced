package com.zs.spring_security_advanced.dto;

public record AuthResponse(
        String accessToken,
        String refreshToken,
        String tokenType,
        String email,
        String role) {
    public static AuthResponse of(String access, String refresh, String email, String role) {
        return new AuthResponse(access, refresh, "Bearer", email, role);
    }
}
