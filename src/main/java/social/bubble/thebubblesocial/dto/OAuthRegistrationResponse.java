package social.bubble.thebubblesocial.dto;

import lombok.Data;

@Data
public class OAuthRegistrationResponse {
    private String email;
    private String redirectUrl;

    public OAuthRegistrationResponse(String email, String redirectUrl) {
        this.email = email;
        this.redirectUrl = redirectUrl;
    }
}
