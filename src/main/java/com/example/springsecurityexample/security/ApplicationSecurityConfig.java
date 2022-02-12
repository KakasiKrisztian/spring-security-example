package com.example.springsecurityexample.security;

import com.example.springsecurityexample.auth.ApplicationUserService;
import com.example.springsecurityexample.jwt.JwtConfig;
import com.example.springsecurityexample.jwt.JwtTokenVerifier;
import com.example.springsecurityexample.jwt.JwtUsernameAndPasswordAuthenticationFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.method.configuration.EnableGlobalMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.csrf.CookieCsrfTokenRepository;
import org.springframework.web.servlet.config.annotation.EnableWebMvc;

import javax.crypto.SecretKey;
import java.util.concurrent.TimeUnit;

import static com.example.springsecurityexample.security.ApplicationUserPermission.*;
import static com.example.springsecurityexample.security.ApplicationUserRole.*;

@Configuration
@EnableWebMvc
@RequiredArgsConstructor
//This annotation needed for @PreAuthorize in controller
@EnableGlobalMethodSecurity(prePostEnabled = true)
public class ApplicationSecurityConfig extends WebSecurityConfigurerAdapter {

    private final ApplicationUserService applicationUserService;

    private final PasswordEncoder passwordEncoder;

    private final SecretKey secretKey;

    private final JwtConfig jwtConfig;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .csrf().disable()
                .sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .addFilter(new JwtUsernameAndPasswordAuthenticationFilter(authenticationManager(), jwtConfig, secretKey))
                .addFilterAfter(new JwtTokenVerifier(secretKey, jwtConfig), JwtUsernameAndPasswordAuthenticationFilter.class)
                .authorizeRequests()
                .antMatchers("/", "index", "/css/*", "/js/*").permitAll()
                .antMatchers("/api/**").hasRole(STUDENT.name())
                .anyRequest()
                .authenticated();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.authenticationProvider(daoAuthenticationProvider());
    }

    @Bean
    public DaoAuthenticationProvider daoAuthenticationProvider(){
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(passwordEncoder);
        provider.setUserDetailsService(applicationUserService);
        return provider;
    }

//    @Override
//    @Bean
//    protected UserDetailsService userDetailsService() {
//        UserDetails mihaiALexUser = User.builder()
//                .username("mihaialex")
//                .password(passwordEncoder.encode("password"))
////                .roles(STUDENT.name())
//                .authorities(STUDENT.getGrantedAuthorities())
//                .build();
//
//        UserDetails mariaUser = User.builder()
//                .username("maria")
//                .password(passwordEncoder.encode("pass123"))
//                .authorities(ADMIN.getGrantedAuthorities())
//                .build();
//
//        UserDetails tomUser = User.builder()
//                .username("tom")
//                .password(passwordEncoder.encode("pass1234"))
//                .authorities(ADMINTRAINEE.getGrantedAuthorities())
//                .build();
//
//        return new InMemoryUserDetailsManager(
//                mihaiALexUser,
//                mariaUser,
//                tomUser
//        );
//    }
}
