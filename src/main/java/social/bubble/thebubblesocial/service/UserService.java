package social.bubble.thebubblesocial.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import social.bubble.thebubblesocial.model.User;
import social.bubble.thebubblesocial.repository.UserRepository;

import java.util.Collections;
import java.util.Optional;

@Service
public class UserService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseGet(() -> userRepository.findByOauthProviderId(username)
                        .orElseThrow(() -> new UsernameNotFoundException("User not found")));
        return new org.springframework.security.core.userdetails.User(
                user.getUsername(), user.getPassword(), Collections.emptyList()
        );
    }

    private void updateExistingUser(User existingUser, User oauthUserData) {
        // Update logic...
        userRepository.save(existingUser);
    }

    private void createUserWithOAuthData(User oauthUserData) {
        // Creation logic...
        userRepository.save(oauthUserData);
    }

    public void registerUser(User user) {
        userRepository.save(user);
    }

    public User registerOrUpdateOAuthUser(User user) {
        Optional<User> existingUser = userRepository.findByEmail(user.getEmail());

        if (existingUser.isPresent()) {
            updateExistingUser(existingUser.get(), user);
            return existingUser.get();
        } else {
            createUserWithOAuthData(user);
            return user;
        }
    }
}

