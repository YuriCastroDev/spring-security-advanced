package com.zs.spring_security_advanced.controller;

import com.zs.spring_security_advanced.entity.SecurityEvent;
import com.zs.spring_security_advanced.repository.SecurityEventRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/admin/security-events")
@RequiredArgsConstructor
public class SecurityEventController {

    private final SecurityEventRepository eventRepository;

    @GetMapping
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<SecurityEvent>> getAllEvents() {
        return ResponseEntity.ok(eventRepository.findAll());
    }

    @GetMapping("/user/{email}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<SecurityEvent>> getByUser(@PathVariable String email) {
        return ResponseEntity.ok(eventRepository.findByEmailOrderByOccurredAtDesc(email));
    }

    @GetMapping("/type/{type}")
    @PreAuthorize("hasRole('ROLE_ADMIN')")
    public ResponseEntity<List<SecurityEvent>> getByType(@PathVariable String type) {
        return ResponseEntity.ok(eventRepository.findByEventTypeOrderByOccurredAtDesc(type.toUpperCase()));
    }
}
