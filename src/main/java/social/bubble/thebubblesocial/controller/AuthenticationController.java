package social.bubble.thebubblesocial.controller;

import com.auth0.jwt.JWT;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.http.*;
import jakarta.validation.Valid;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.http.*;
import org.springframework.util.MultiValueMap;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import social.bubble.thebubblesocial.dto.*;
import social.bubble.thebubblesocial.model.User;
import social.bubble.thebubblesocial.repository.UserRepository;
import social.bubble.thebubblesocial.security.JwtTokenProvider;
import social.bubble.thebubblesocial.service.UserService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.util.Map;

@RestController
@CrossOrigin(origins = {"https://accounts.google.com", "http://localhost:3000"})
@RequestMapping("/auth")
public class AuthenticationController {

    private final RestTemplate restTemplate;
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

    @Value("${spring.security.oauth2.client.registration.google.client-id}")
    private String googleClientId;

    @Value("${spring.security.oauth2.client.registration.google.client-secret}")
    private String googleClientSecret;

    public AuthenticationController(RestTemplateBuilder restTemplateBuilder) {
        this.restTemplate = restTemplateBuilder.build();
    }


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
                if (username == null) {
                    return ResponseEntity.badRequest().body("Invalid refresh token");
                } else if (!userRepository.existsByUsername(username)) {
                    return ResponseEntity.badRequest().body("Invalid refresh token");
                } else {
                    String newToken = jwtTokenProvider.createToken(username);
                    log.info("username: {}", username);
                    return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
                }
            }
        } catch (Exception e) {
            log.info("Exception: {}", e.getMessage());
            return ResponseEntity.badRequest().body("Invalid refresh token");
        }
        return ResponseEntity.badRequest().body("Invalid request");
    }

    @GetMapping("/oauth2/google/callback")
    public ResponseEntity<?> handleGoogleCallback(@RequestParam("state") String state, @RequestParam("code") String code,
                                                  @RequestParam("scope") String scope, @RequestParam("authuser") String authuser,
                                                  @RequestParam("prompt") String prompt, HttpServletResponse servletResponse,
                                                  HttpSession session) throws JsonProcessingException {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_FORM_URLENCODED);

        MultiValueMap<String, String> map= new LinkedMultiValueMap<>();


        map.add("client_id", googleClientId);
        map.add("client_secret", googleClientSecret);
        map.add("code", code);
        map.add("grant_type", "authorization_code");
        map.add("redirect_uri", "https://thebubble.social.ngrok.dev/auth/oauth2/google/callback");

        HttpEntity<MultiValueMap<String, String>> request = new HttpEntity<>(map, headers);

        ResponseEntity<String> response = restTemplate.postForEntity("https://oauth2.googleapis.com/token", request, String.class);
        Map<String, Object> responseMap = new ObjectMapper().readValue(response.getBody(), new TypeReference<Map<String, Object>>() {});

        String accessToken = (String) responseMap.get("access_token");
        String idToken = (String) responseMap.get("id_token");

        DecodedJWT jwt = JWT.decode(idToken);
        String email = jwt.getClaim("email").asString();

        session.setAttribute("accessToken", accessToken);
        session.setAttribute("idToken", idToken);

        if(userRepository.existsByEmail(email)) {
            User user = userRepository.findByEmail(email).get();
            String newToken = jwtTokenProvider.createToken(user.getUsername());
            String refreshToken = jwtTokenProvider.createRefreshToken(user.getUsername());
            return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
        } else {
            String tempToken = jwtTokenProvider.createTempToken(email, idToken);
            URI registrationUri = URI.create(String.format("https://localhost:3000/oauth-registration?tempToken=%s", tempToken));
            return ResponseEntity.status(HttpStatus.FOUND).location(registrationUri).build();
        }
    }

    @PostMapping("/oauth2/register")
    public ResponseEntity<?> completeOAuthRegistration(@RequestBody OAuthUsernameRegistrationToken tempToken
            , HttpSession session) {
        String username = tempToken.getUsername();
        String tempTokenString = tempToken.getTempToken();
        if(userRepository.existsByUsername(username)) {
            return ResponseEntity.badRequest().body("Username already exists");
        }
        try {
            if (!jwtTokenProvider.validateToken(tempTokenString)) {
                return ResponseEntity.badRequest().body("Invalid temp token");
            }
            else {
                DecodedJWT jwt = JWT.decode(tempTokenString);
                String email = jwt.getSubject();
                DecodedJWT idJwt = JWT.decode(jwt.getId());
                var user = new User(username, email, "google", idJwt.getSubject());
                userService.registerUser(user);
                String newToken = jwtTokenProvider.createToken(user.getUsername());
                String refreshToken = jwtTokenProvider.createRefreshToken(user.getUsername());
                return ResponseEntity.ok(new JwtResponse(newToken, refreshToken));
            }
        } catch (JWTDecodeException e) {
            return ResponseEntity.badRequest().body("Invalid temp token");
        }
    }

    @GetMapping("/oauth2/apple/callback")
    public ResponseEntity<?> handleAppleCallback(@RequestParam String code) {
        log.info("Apple code: {}", code);
        return ResponseEntity.ok("Apple callback");
    }
}