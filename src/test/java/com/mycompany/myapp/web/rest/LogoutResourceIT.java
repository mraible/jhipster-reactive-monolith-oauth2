package com.mycompany.myapp.web.rest;

import com.mycompany.myapp.JhipsterApp;
import com.mycompany.myapp.config.TestSecurityConfiguration;
import com.mycompany.myapp.security.AuthoritiesConstants;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.MediaType;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.test.web.reactive.server.WebTestClient;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;

import static org.springframework.security.test.web.reactive.server.SecurityMockServerConfigurers.*;

/**
 * Integration tests for the {@link LogoutResource} REST controller.
 */
@SpringBootTest(classes = {JhipsterApp.class, TestSecurityConfiguration.class})
public class LogoutResourceIT {

    @Autowired
    private ReactiveClientRegistrationRepository registrations;

    @Autowired
    private ApplicationContext context;

    private final static String ID_TOKEN = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9" +
        ".eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsIm" +
        "p0aSI6ImQzNWRmMTRkLTA5ZjYtNDhmZi04YTkzLTdjNmYwMzM5MzE1OSIsImlhdCI6MTU0M" +
        "Tk3MTU4MywiZXhwIjoxNTQxOTc1MTgzfQ.QaQOarmV8xEUYV7yvWzX3cUE_4W1luMcWCwpr" +
        "oqqUrg";

    WebTestClient webTestClient;

    OidcIdToken idToken;

    @BeforeEach
    public void before() {
        this.webTestClient = WebTestClient.bindToApplicationContext(this.context)
            .apply(springSecurity())
            .configureClient()
            .build();

        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", "ROLE_USER");
        claims.put("sub", 123);
        this.idToken = new OidcIdToken(ID_TOKEN, Instant.now(),
            Instant.now().plusSeconds(60), claims);
    }

    @Test
    public void getLogoutInformation() throws Exception {
        Mono<String> logoutUrl = this.registrations.findByRegistrationId("oidc")
            .map(oidc -> oidc.getProviderDetails().getConfigurationMetadata()
                .get("end_session_endpoint").toString());

        this.webTestClient.mutateWith(csrf())
            .mutateWith(mockAuthentication(authenticationToken(idToken)))
            .post().uri("/api/logout").exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MediaType.APPLICATION_JSON_VALUE)
            .expectBody()
            .jsonPath("$.logoutUrl").isEqualTo(logoutUrl.toString())
            .jsonPath("$.idToken").isEqualTo(ID_TOKEN);
    }

    private OAuth2AuthenticationToken authenticationToken(OidcIdToken idToken) {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        authorities.add(new SimpleGrantedAuthority(AuthoritiesConstants.USER));
        OidcUser user = new DefaultOidcUser(authorities, idToken);
        return new OAuth2AuthenticationToken(user, authorities, "oidc");
    }
}
