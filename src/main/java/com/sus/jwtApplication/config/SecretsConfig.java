package com.sus.jwtApplication.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.PropertySource;

@Configuration
@PropertySource("classpath:application-secrets.yml")
public class SecretsConfig {


}
