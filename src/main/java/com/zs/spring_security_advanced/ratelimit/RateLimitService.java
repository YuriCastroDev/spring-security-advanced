package com.zs.spring_security_advanced.ratelimit;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.stereotype.Service;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Slf4j
@Service
@RequiredArgsConstructor
public class RateLimitService {

    private static final String RATE_LIMIT_PREFIX = "rate:limit:";

    private final StringRedisTemplate redisTemplate;

    @Value("${app.security.rate-limit-requests}")
    private int maxRequests;

    @Value("${app.security.rate-limit-window-seconds}")
    private long windowSeconds;

    public boolean isAllowed(String identifier) {
        String key = RATE_LIMIT_PREFIX + identifier;
        Long count = redisTemplate.opsForValue().increment(key);

        if (count == 1) {
            // Primeira requisição na janela — define o TTL
            redisTemplate.expire(key, Duration.ofSeconds(windowSeconds));
        }

        if (count > maxRequests) {
            log.warn("Rate limit exceeded for: {} ({} requests in {}s window)", identifier, count, windowSeconds);
            return false;
        }

        return true;
    }

    public long getRemainingRequests(String identifier) {
        String key = RATE_LIMIT_PREFIX + identifier;
        String value = redisTemplate.opsForValue().get(key);
        if (value == null) return maxRequests;
        return Math.max(0, maxRequests - Long.parseLong(value));
    }

    public long getWindowExpiry(String identifier) {
        String key = RATE_LIMIT_PREFIX + identifier;
        Long ttl = redisTemplate.getExpire(key, TimeUnit.SECONDS);
        return ttl != null ? ttl : 0;
    }
}
