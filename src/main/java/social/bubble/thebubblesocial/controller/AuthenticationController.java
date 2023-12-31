package social.bubble.thebubblesocial.controller;

import jakarta.validation.Valid;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import social.bubble.thebubblesocial.dto.JwtResponse;
import social.bubble.thebubblesocial.dto.LoginRequest;
import social.bubble.thebubblesocial.dto.RefreshTokenRequest;
import social.bubble.thebubblesocial.model.User;
import social.bubble.thebubblesocial.repository.UserRepository;
import social.bubble.thebubblesocial.security.JwtTokenProvider;
import social.bubble.thebubblesocial.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@RestController
@CrossOrigin(origins = "http://localhost:3000")
@RequestMapping("/auth")
public class AuthenticationController {
    private static final Logger log = LoggerFactory.getLogger(AuthenticationController.class);

    @Autowired
    private UserService userService;

    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserRepository userRepository;

    @PostMapping("/register")
    public ResponseEntity<?> registerUser(@Valid @RequestBody User user) {
        log.info("Password before saving: {}", user.getPassword());
        if (!isPasswordValid(user.getPassword())) {
            return ResponseEntity.badRequest().body("Password does not meet length requirements.");
        }
        if (userRepository.existsByUsername(user.getUsername())) {
            return ResponseEntity.badRequest().body("Error: Username " + user.getUsername() + " is already taken!");
        }
        if (userRepository.existsByEmail(user.getEmail())) {
            return ResponseEntity.badRequest().body("Error: Email is already in use!");
        }

        // Encode password
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        log.info("Encoded password: {}", user.getPassword());

        // Save user
        userRepository.save(user);

        String newToken = jwtTokenProvider.createToken(user.getUsername());
        String refreshToken = jwtTokenProvider.createRefreshToken(user.getUsername());
        return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
    }

    private boolean isPasswordValid(String password) {
        return password.length() >= 10 && password.length() <= 25 && !password.contains(" ")
                && password.matches(".*\\d.*") && password.matches(".*[a-z].*")
                && password.matches(".*[A-Z].*");
    }

    @PostMapping("/login")
    public ResponseEntity<?> loginUser(@RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(
                            loginRequest.getUsername(),
                            loginRequest.getPassword()
                    )
            );

            String newToken = jwtTokenProvider.createToken(loginRequest.getUsername());
            String refreshToken = jwtTokenProvider.createRefreshToken(loginRequest.getUsername());
            return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
        } catch (AuthenticationException e) {
            return ResponseEntity.badRequest().body("Invalid username/password");
        }
    }

    @PostMapping("/refresh-token")
    public ResponseEntity<?> refreshToken(@RequestBody RefreshTokenRequest request) {
        String refreshToken = request.getRefreshToken();
        log.info("Refresh token: {}", refreshToken);
        try {

            if (jwtTokenProvider.validateToken(refreshToken)) {
                String username = jwtTokenProvider.getUsername(refreshToken);
                String newToken = jwtTokenProvider.createToken(username);
                log.info("username: {}", username);
                return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
            }
        } catch (Exception e) {
            log.info("Exception: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }
        return ResponseEntity.badRequest().body("Invalid request");
    }
}