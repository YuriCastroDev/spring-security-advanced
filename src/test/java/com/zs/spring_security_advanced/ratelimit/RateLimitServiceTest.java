package com.zs.spring_security_advanced.ratelimit;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.ValueOperations;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitServiceTest {

    @Mock private StringRedisTemplate redisTemplate;
    @Mock private ValueOperations<String, String> valueOperations;

    @InjectMocks private RateLimitService rateLimitService;

    @BeforeEach
    void setUp() {
        ReflectionTestUtils.setField(rateLimitService, "maxRequests", 5);
        ReflectionTestUtils.setField(rateLimitService, "windowSeconds", 60L);
        when(redisTemplate.opsForValue()).thenReturn(valueOperations);
    }

    @Test
    void shouldAllowRequestUnderLimit() {
        when(valueOperations.increment(anyString())).thenReturn(1L);

        assertThat(rateLimitService.isAllowed("127.0.0.1")).isTrue();
    }

    @Test
    void shouldAllowRequestAtLimit() {
        when(valueOperations.increment(anyString())).thenReturn(5L);

        assertThat(rateLimitService.isAllowed("127.0.0.1")).isTrue();
    }

    @Test
    void shouldBlockRequestOverLimit() {
        when(valueOperations.increment(anyString())).thenReturn(6L);

        assertThat(rateLimitService.isAllowed("127.0.0.1")).isFalse();
    }

    @Test
    void shouldSetTtlOnFirstRequest() {
        when(valueOperations.increment(anyString())).thenReturn(1L);

        rateLimitService.isAllowed("127.0.0.1");

        verify(redisTemplate).expire(anyString(), eq(java.time.Duration.ofSeconds(60)));
    }

    @Test
    void shouldNotSetTtlOnSubsequentRequests() {
        when(valueOperations.increment(anyString())).thenReturn(3L);

        rateLimitService.isAllowed("127.0.0.1");

        verify(redisTemplate, never()).expire(anyString(), any(java.time.Duration.class));
    }
}
