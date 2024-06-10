package social.bubble.thebubblesocial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import social.bubble.thebubblesocial.model.User;

import java.util.Map;

public class BubbleOidcUserService extends OidcUserService {

    @Autowired
    private UserService userService;

    @Override
    public OidcUser loadUser(OidcUserRequest userRequest) throws OAuth2AuthenticationException {
        OidcUser oidcUser = super.loadUser(userRequest);
        Map<String, Object> attributes = oidcUser.getAttributes();

        String oauthProvider = userRequest.getClientRegistration().getRegistrationId();
        String oauthProviderId = oidcUser.getName();

        userService.registerOrUpdateOAuthUser(extractUserData(attributes, oauthProvider, oauthProviderId));

        return oidcUser;
    }

    private User extractUserData(Map<String, Object> attributes, String oauthProvider, String oauthProviderId) {
        String username = (String) attributes.getOrDefault("name", "");
        String email = (String) attributes.getOrDefault("email", "");

        return new User(username, email, oauthProvider, oauthProviderId);
    }
}
