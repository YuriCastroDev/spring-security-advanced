package com.zs.spring_security_advanced.auth;

import com.zs.spring_security_advanced.dto.LoginRequest;
import com.zs.spring_security_advanced.dto.RegisterRequest;
import com.zs.spring_security_advanced.entity.Role;
import com.zs.spring_security_advanced.entity.User;
import com.zs.spring_security_advanced.jwt.JwtService;
import com.zs.spring_security_advanced.repository.SecurityEventRepository;
import com.zs.spring_security_advanced.repository.UserRepository;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.test.util.ReflectionTestUtils;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AuthServiceTest {

    @Mock private UserRepository userRepository;
    @Mock private SecurityEventRepository eventRepository;
    @Mock private JwtService jwtService;
    @Mock private PasswordEncoder passwordEncoder;

    @InjectMocks private AuthService authService;

    private User user;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(authService, "maxAttempts", 5);
        ReflectionTestUtils.setField(authService, "lockoutMinutes", 15);

        user = User.builder()
                .id(UUID.randomUUID())
                .email("joao@email.com")
                .password("encoded")
                .role(Role.ROLE_USER)
                .failedLoginAttempts(0)
                .build();
    }

    @Test
    void shouldRegisterUser() {
        RegisterRequest request = new RegisterRequest("João", "joao@email.com", "123456");
        when(userRepository.existsByEmail("joao@email.com")).thenReturn(false);
        when(passwordEncoder.encode("123456")).thenReturn("encoded");
        when(userRepository.save(any())).thenReturn(user);
        when(jwtService.generateToken(any())).thenReturn("access");
        when(jwtService.generateRefreshToken(any())).thenReturn("refresh");

        var response = authService.register(request);

        assertThat(response.accessToken()).isEqualTo("access");
        verify(userRepository).save(any(User.class));
    }

    @Test
    void shouldThrowOnDuplicateEmail() {
        when(userRepository.existsByEmail("joao@email.com")).thenReturn(true);
        assertThatThrownBy(() -> authService.register(new RegisterRequest("João", "joao@email.com", "123")))
                .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldLoginSuccessfully() {
        when(userRepository.findByEmail("joao@email.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("123456", "encoded")).thenReturn(true);
        when(jwtService.generateToken(any())).thenReturn("access");
        when(jwtService.generateRefreshToken(any())).thenReturn("refresh");
        when(userRepository.save(any())).thenReturn(user);

        var response = authService.login(new LoginRequest("joao@email.com", "123456"), "127.0.0.1");

        assertThat(response.accessToken()).isEqualTo("access");
        verify(eventRepository).save(argThat(e -> e.getEventType().equals("LOGIN_SUCCESS")));
    }

    @Test
    void shouldIncrementFailedAttemptsOnWrongPassword() {
        when(userRepository.findByEmail("joao@email.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("ERRADA", "encoded")).thenReturn(false);
        when(userRepository.save(any())).thenReturn(user);

        assertThatThrownBy(() -> authService.login(new LoginRequest("joao@email.com", "ERRADA"), "127.0.0.1"))
                .isInstanceOf(BadCredentialsException.class);

        verify(userRepository).save(argThat(u -> u.getFailedLoginAttempts() == 1));
        verify(eventRepository).save(argThat(e -> e.getEventType().equals("LOGIN_FAILED")));
    }

    @Test
    void shouldLockAccountAfterMaxAttempts() {
        user.setFailedLoginAttempts(4); // já tem 4, a próxima vai bloquear
        when(userRepository.findByEmail("joao@email.com")).thenReturn(Optional.of(user));
        when(passwordEncoder.matches("ERRADA", "encoded")).thenReturn(false);
        when(userRepository.save(any())).thenReturn(user);

        assertThatThrownBy(() -> authService.login(new LoginRequest("joao@email.com", "ERRADA"), "127.0.0.1"))
                .isInstanceOf(BadCredentialsException.class);

        verify(userRepository).save(argThat(u -> u.getLockedUntil() != null));
        verify(eventRepository).save(argThat(e -> e.getEventType().equals("ACCOUNT_LOCKED")));
    }

    @Test
    void shouldThrowLockedExceptionForLockedAccount() {
        user.setLockedUntil(LocalDateTime.now().plusMinutes(10));
        when(userRepository.findByEmail("joao@email.com")).thenReturn(Optional.of(user));

        assertThatThrownBy(() -> authService.login(new LoginRequest("joao@email.com", "123456"), "127.0.0.1"))
                .isInstanceOf(LockedException.class);
    }
}
