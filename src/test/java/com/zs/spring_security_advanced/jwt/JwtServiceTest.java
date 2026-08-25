package com.zs.spring_security_advanced.jwt;

import com.zs.spring_security_advanced.entity.Role;
import com.zs.spring_security_advanced.entity.User;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class JwtServiceTest {

    @Mock
    private StringRedisTemplate redisTemplate;

    @Mock
    private ValueOperations<String, String> valueOperations;

    @InjectMocks
    private JwtService jwtService;

    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(jwtService, "secretKey",
                "404E635266556A586E3272357538782F413F4428472B4B6250645367566B5970");
        ReflectionTestUtils.setField(jwtService, "jwtExpiration", 86400000L);
        ReflectionTestUtils.setField(jwtService, "refreshExpiration", 604800000L);

        user = User.builder()
                .id(UUID.randomUUID())
                .email("joao@email.com")
                .password("encoded")
                .role(Role.ROLE_USER)
                .build();

        lenient().when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void shouldGenerateAndValidateToken() {
        when(redisTemplate.hasKey(anyString())).thenReturn(false);

        String token = jwtService.generateToken(user);

        assertThat(token).isNotNull();
        assertThat(jwtService.extractUsername(token)).isEqualTo("joao@email.com");
        assertThat(jwtService.isTokenValid(token, user)).isTrue();
    }

    @Test
    void shouldBlacklistToken() {
        String token = jwtService.generateToken(user);

        jwtService.blacklistToken(token);

        verify(valueOperations).set(
                argThat(k -> k.startsWith("jwt:blacklist:")),
                eq("blacklisted"),
                any(java.time.Duration.class)
        );
    }

    @Test
    void shouldReturnFalseForBlacklistedToken() {
        String token = jwtService.generateToken(user);
        when(redisTemplate.hasKey(anyString())).thenReturn(true);

        assertThat(jwtService.isTokenValid(token, user)).isFalse();
    }

    @Test
    void shouldReturnFalseForWrongUser() {
        when(redisTemplate.hasKey(anyString())).thenReturn(false);
        String token = jwtService.generateToken(user);

        User other = User.builder().email("outro@email.com").role(Role.ROLE_USER).build();

        assertThat(jwtService.isTokenValid(token, other)).isFalse();
    }

    @Test
    void shouldCheckBlacklistOnValidation() {
        when(redisTemplate.hasKey(anyString())).thenReturn(false);
        String token = jwtService.generateToken(user);

        jwtService.isTokenValid(token, user);

        verify(redisTemplate).hasKey(anyString());
    }
}
