package social.bubble.thebubblesocial.dto;

import lombok.Data;

@Data
public class JwtResponse {
    private String userToken;
    private String refreshToken; // Added field for refresh token

    public JwtResponse(String userToken, String refreshToken) {
        this.userToken = userToken;
        this.refreshToken = refreshToken; // Initialize refresh token
    }

    // Getters and setters
}