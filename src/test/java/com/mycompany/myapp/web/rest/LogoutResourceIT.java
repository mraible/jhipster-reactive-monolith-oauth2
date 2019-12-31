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
import java.util.*;

import static com.mycompany.myapp.web.rest.TestUtil.ID_TOKEN;
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

    private WebTestClient webTestClient;

    private OidcIdToken idToken;

    @BeforeEach
    public void before() {
        this.webTestClient = WebTestClient.bindToApplicationContext(this.context)
            .apply(springSecurity())
            .configureClient()
            .build();

        Map<String, Object> claims = new HashMap<>();
        claims.put("groups", Collections.singletonList("ROLE_USER"));
        claims.put("sub", 123);
        this.idToken = new OidcIdToken(ID_TOKEN, Instant.now(),
            Instant.now().plusSeconds(60), claims);
    }

    @Test
    public void getLogoutInformation() {
        Mono<String> logoutUrl = this.registrations.findByRegistrationId("oidc")
            .map(oidc -> oidc.getProviderDetails().getConfigurationMetadata()
                .get("end_session_endpoint").toString());

        this.webTestClient.mutateWith(csrf())
            .mutateWith(mockAuthentication(TestUtil.authenticationToken(idToken)))
            .post().uri("/api/logout").exchange()
            .expectStatus().isOk()
            .expectHeader().contentType(MediaType.APPLICATION_JSON_VALUE)
            .expectBody()
            .jsonPath("$.logoutUrl").isEqualTo(logoutUrl.toString())
            .jsonPath("$.idToken").isEqualTo(ID_TOKEN);
    }

}
