package social.bubble.thebubblesocial.repository;

import org.springframework.data.jpa.repository.JpaRepository;
import social.bubble.thebubblesocial.model.User;

import java.util.Optional;

public interface UserRepository extends JpaRepository<User, Long> {
    Optional<User> findByUsername(String username);

    boolean existsByUsername(String username);

    boolean existsByEmail(String email);
}
