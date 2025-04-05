package com.uqac.bruteforce_ssh.dto;

import lombok.Getter;
import lombok.Setter;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration
@Getter
@Setter
@ConfigurationProperties(prefix = "api.externe")
public class ApiProperties {
    private String url;

    // Getter & Setter
}
