package com.example.spring.AuthorizationServerApplication;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

@Configuration
@Order(1)
public class SecurityConfiguration extends WebSecurityConfigurerAdapter {

    @Value("${user.oauth.custom-client.user.username}")
    private String username;
    @Value("${user.oauth.custom-client.user.password}")
    private String password;

    @Value("${user.oauth.custom-client1.user.username}")
    private String username1;
    @Value("${user.oauth.custom-client1.user.password}")
    private String password1;

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.requestMatchers()
                .antMatchers("/login", "/oauth/authorize")
                .and()
                .authorizeRequests()
                .anyRequest().authenticated()
                .and()
                .formLogin().permitAll();
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication()
                .withUser(username)
                .password(passwordEncoder().encode(password))
                .roles("USER")
                .and()
                .withUser(username1)
                .password(passwordEncoder().encode(password1))
                .roles("ADMIN");

    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}