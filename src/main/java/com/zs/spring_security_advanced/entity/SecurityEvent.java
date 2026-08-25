package com.zs.spring_security_advanced.entity;

import jakarta.persistence.*;
import lombok.*;

import java.time.LocalDateTime;
import java.util.UUID;

@Entity
@Table(name = "security_events")
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class SecurityEvent {

    @Id
    @GeneratedValue(strategy = GenerationType.UUID)
    private UUID id;

    private String email;
    private String eventType;
    private String ipAddress;
    private String details;
    private LocalDateTime occurredAt;

    @PrePersist
    public void prePersist() {
        this.occurredAt = LocalDateTime.now();
    }
}
