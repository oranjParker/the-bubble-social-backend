package social.bubble.thebubblesocial;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import social.bubble.thebubblesocial.service.AppleTokenService;

@SpringBootApplication
public class TheBubbleSocialApplication {

	public static void main(String[] args) {
		SpringApplication.run(TheBubbleSocialApplication.class, args);
	}

}
