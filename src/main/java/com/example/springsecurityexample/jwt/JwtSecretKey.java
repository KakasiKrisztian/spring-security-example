package com.example.springsecurityexample.jwt;

import io.jsonwebtoken.security.Keys;
import lombok.AllArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.crypto.SecretKey;

@Configuration
@AllArgsConstructor
public class JwtSecretKey {

    private final JwtConfig jwtConfigl;

    @Bean
    public SecretKey secretKey(){
        return Keys.hmacShaKeyFor(jwtConfigl.getSecretKey().getBytes());
    }
}
