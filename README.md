# 🔒 Spring Security Advanced

Production-ready security patterns for Spring Boot APIs.  
Implements **JWT blacklist** (real logout), **brute force protection** with account lockout, **Redis-based rate limiting** and **security event logging**.

---

## 🏗️ Architecture

```
[Request]
    │
    ▼
[RateLimitFilter] ── exceeded? ──► 429 Too Many Requests
    │ (Redis counter per IP, 60s window)
    ▼
[JwtAuthenticationFilter]
    │ checks blacklist in Redis
    │── blacklisted? ──► 401 Unauthorized
    ▼
[Spring Security]
    ▼
[Controller]

[POST /api/auth/login]
    └── account locked? ──► 403 LockedException
    └── wrong password? ──► increment failedAttempts
        └── >= 5 attempts? ──► lock account 15min + log ACCOUNT_LOCKED
    └── success ──► reset counter + log LOGIN_SUCCESS + return JWT

[POST /api/auth/logout]
    └── blacklist token in Redis (TTL = token remaining expiry)
    └── log LOGOUT
```

---

## 🛠️ Tech Stack

| Technology | Purpose |
|---|---|
| Java 21 | Language |
| Spring Boot 3.5 | Framework |
| Spring Security 6 | Authentication |
| JJWT 0.12 | JWT |
| Redis 7.2 | Token blacklist + Rate limiting |
| PostgreSQL 16 | User + Security events |
| Docker Compose | Local infrastructure |

---

## ▶️ Running Locally

```bash
docker-compose up -d
./mvnw spring-boot:run
```

```bash
./mvnw test
```

---

## 📮 Endpoints

### Auth
```
POST /api/auth/register  → create account
POST /api/auth/login     → returns JWT (tracks failed attempts)
POST /api/auth/logout    → blacklists token in Redis
```

### Protected
```
GET /api/me                          → current user info + failedAttempts
GET /api/admin/users                 → all users (ADMIN)
GET /api/admin/locked-accounts       → currently locked accounts (ADMIN)
GET /api/admin/security-events       → all security events (ADMIN)
GET /api/admin/security-events/user/{email} → events by user (ADMIN)
GET /api/admin/security-events/type/{type}  → events by type (ADMIN)
```

---

## 🛡️ Security Features

### JWT Blacklist (Real Logout)
When user logs out, the token is stored in Redis with TTL equal to the token's remaining expiry.  
Any request with a blacklisted token returns `401`.

### Brute Force Protection
- 5 failed login attempts → account locked for 15 minutes
- Every attempt is logged as a `SecurityEvent`
- Lock is stored in the database (`lockedUntil` field)
- Successful login resets the counter

### Rate Limiting
- 20 requests per IP per 60-second window
- Counter stored in Redis with TTL
- Exceeding limit returns `429 Too Many Requests`
- Response headers: `X-RateLimit-Limit`, `X-RateLimit-Remaining`, `X-RateLimit-Reset`

### Security Event Logging
Every security-relevant action is persisted:

| Event | Trigger |
|---|---|
| `LOGIN_SUCCESS` | Successful login |
| `LOGIN_FAILED` | Wrong password |
| `ACCOUNT_LOCKED` | Max attempts reached |
| `LOGIN_BLOCKED` | Login attempt on locked account |
| `LOGOUT` | Token blacklisted |

---

## ⚙️ Configuration

```yaml
app:
  security:
    max-login-attempts: 5        # attempts before lockout
    lockout-duration-minutes: 15 # how long account stays locked
    rate-limit-requests: 20      # max requests per window
    rate-limit-window-seconds: 60 # window size
```

---

## 🧪 Tests

| Test | What it covers |
|---|---|
| `JwtServiceTest` | Token generation, blacklist check, invalid after blacklist |
| `AuthServiceTest` | Register, login, failed attempts counter, lockout at max, locked exception |
| `RateLimitServiceTest` | Allow under limit, allow at limit, block over limit, TTL set on first request |
