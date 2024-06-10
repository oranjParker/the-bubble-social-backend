package social.bubble.thebubblesocial.dto;

import lombok.Data;

@Data
public class OAuthUsernameRegistrationToken {
    private String username;
    private String tempToken;
}