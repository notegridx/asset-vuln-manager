package dev.notegridx.security.assetvulnmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;


@SpringBootApplication
@EnableScheduling
public class AssetVulnManagerApplication {

	public static void main(String[] args) {
		SpringApplication.run(AssetVulnManagerApplication.class, args);
	}

}
