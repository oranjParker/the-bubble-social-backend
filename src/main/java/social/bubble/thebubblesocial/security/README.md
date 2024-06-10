# Security Configuration for The Bubble Social

The `SecurityConfiguration` class in the `social.bubble.thebubblesocial.security` package configures the security aspects of The Bubble Social application. This includes authentication mechanisms, security filter chains, and OAuth 2.0 integration for social login functionality.

## Components and Configuration

### UserDetailsService
- Injected `UserDetailsService` loads user-specific data, mainly used in form-based login and JWT token filter.

### JwtTokenFilter
- `JwtTokenFilter` intercepts HTTP requests to check and validate JWT tokens, setting authentication in the security context.

### Google Client Configuration
- Uses properties `spring.security.oauth2.client.registration.google.client-id` and `spring.security.oauth2.client.registration.google.client-secret` for Google OAuth 2.0 client setup.

### Password Encoder
- A `PasswordEncoder` bean is defined for secure password encoding using BCrypt hashing.

### Security Filter Chain
- Configures `HttpSecurity` to establish security settings, including CSRF protection, URL authorization, and JWT token filter integration.

### OAuth2 Login Configuration
- Integrates OAuth 2.0 login with client registration repository setup and user information endpoint configuration.

### Authentication Manager
- Configures `AuthenticationManager` with user details service and password encoder for the authentication process.

### Client Registration Repository
- Defines client registrations for OAuth 2.0 providers, currently configured for Google.

### Google Client Registration
- Creates `ClientRegistration` for Google with client ID, secret, URIs, scopes, and other details.

### OIDC User Service
- Returns an `OidcUserService` instance for loading user details from OAuth 2.0 provider UserInfo endpoints.

## Usage and Integration

- Automatically detected and applied by Spring Boot, integrating with the application's authentication and authorization processes.

## Future Enhancements (TODOs)
- **Customize `OidcUserService`**: Further customization required for handling specific OAuth 2.0 user details.

## Conclusion

The `SecurityConfiguration` class is a cornerstone of the security infrastructure of The Bubble Social, providing robust authentication including form-based and OAuth 2.0 logins, ensuring a secure and flexible system.
