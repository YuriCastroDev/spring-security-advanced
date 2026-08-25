package com.zs.spring_security_advanced.repository;

import com.zs.spring_security_advanced.entity.SecurityEvent;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.UUID;

public interface SecurityEventRepository extends JpaRepository<SecurityEvent, UUID> {
    List<SecurityEvent> findByEmailOrderByOccurredAtDesc(String email);

    List<SecurityEvent> findByEventTypeOrderByOccurredAtDesc(String eventType);
}
