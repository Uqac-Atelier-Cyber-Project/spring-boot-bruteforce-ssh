package com.uqac.bruteforce_ssh;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@Configuration
@EnableAsync
public class BruteforceSshApplication {

	public static void main(String[] args) {
		SpringApplication.run(BruteforceSshApplication.class, args);
	}

}
