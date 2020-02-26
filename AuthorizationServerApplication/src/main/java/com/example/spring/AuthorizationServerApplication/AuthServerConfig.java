package com.example.spring.AuthorizationServerApplication;


import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;

@Configuration
@EnableAuthorizationServer
public class AuthServerConfig extends AuthorizationServerConfigurerAdapter {

    @Value("${user.oauth.custom-client.clientId}")
    private String ClientID;
    @Value("${user.oauth.custom-client.clientSecret}")
    private String ClientSecret;
    @Value("${user.oauth.custom-client.redirectUris}")
    private String RedirectURLs;

    @Value("${user.oauth.custom-client1.clientId}")
    private String ClientID1;
    @Value("${user.oauth.custom-client1.clientSecret}")
    private String ClientSecret1;
    @Value("${user.oauth.custom-client1.redirectUris}")
    private String RedirectURLs1;

    private final PasswordEncoder passwordEncoder;

    public AuthServerConfig(PasswordEncoder passwordEncoder) {
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public void configure(
            AuthorizationServerSecurityConfigurer oauthServer) throws Exception {
        oauthServer.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()");
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients.inMemory()
                .withClient(ClientID)
                .secret(passwordEncoder.encode(ClientSecret))
                .authorizedGrantTypes("authorization_code")
                .scopes("user_info")
                .autoApprove(true)
                .redirectUris(RedirectURLs)
        .and()
                .withClient(ClientID1)
                .secret(passwordEncoder.encode(ClientSecret1))
                .authorizedGrantTypes("authorization_code")
                .scopes("user_info")
                .autoApprove(true)
                .redirectUris(RedirectURLs1);
    }
}