package com.mycompany.myapp.config;

import com.mycompany.myapp.security.AuthoritiesConstants;
import com.mycompany.myapp.security.SecurityUtils;
import com.mycompany.myapp.security.oauth2.AudienceValidator;
import com.mycompany.myapp.security.oauth2.JwtAuthorityExtractor;
import com.mycompany.myapp.service.AuditEventService;
import io.github.jhipster.config.JHipsterProperties;
import io.github.jhipster.web.filter.reactive.CookieCsrfFilter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Import;
import org.springframework.core.convert.converter.Converter;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.config.annotation.method.configuration.EnableReactiveMethodSecurity;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcReactiveOAuth2UserService;
import org.springframework.security.oauth2.client.oidc.userinfo.OidcUserRequest;
import org.springframework.security.oauth2.client.userinfo.ReactiveOAuth2UserService;
import org.springframework.security.oauth2.core.DelegatingOAuth2TokenValidator;
import org.springframework.security.oauth2.core.OAuth2TokenValidator;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUserAuthority;
import org.springframework.security.oauth2.jwt.*;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.ReactiveJwtAuthenticationConverterAdapter;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.csrf.CookieServerCsrfTokenRepository;
import org.springframework.security.web.server.header.ReferrerPolicyServerHttpHeadersWriter;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.OrServerWebExchangeMatcher;
import org.zalando.problem.spring.webflux.advice.security.SecurityProblemSupport;
import reactor.core.publisher.Mono;

import java.util.HashSet;
import java.util.Set;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

@EnableWebFluxSecurity
@EnableReactiveMethodSecurity
@Import(SecurityProblemSupport.class)
public class SecurityConfiguration {

    @Value("${spring.security.oauth2.client.provider.oidc.issuer-uri}")
    private String issuerUri;

    private final JHipsterProperties jHipsterProperties;
    private final AuditEventService auditEventService;
    private final SecurityProblemSupport problemSupport;

    public SecurityConfiguration(AuditEventService auditEventService, JHipsterProperties jHipsterProperties, SecurityProblemSupport problemSupport) {
        this.auditEventService = auditEventService;
        this.jHipsterProperties = jHipsterProperties;
        this.problemSupport = problemSupport;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        // @formatter:off
        http
            .securityMatcher(new NegatedServerWebExchangeMatcher(new OrServerWebExchangeMatcher(
                pathMatchers("/app/**", "/i18n/**", "/content/**", "/swagger-ui/index.html", "/test/**"),
                pathMatchers(HttpMethod.OPTIONS, "/**")
            )))
            .csrf()
                .csrfTokenRepository(CookieServerCsrfTokenRepository.withHttpOnlyFalse())
            .and()
            // See https://github.com/spring-projects/spring-security/issues/5766
            .addFilterAt(new CookieCsrfFilter(), SecurityWebFiltersOrder.REACTOR_CONTEXT)
            .exceptionHandling()
                .authenticationEntryPoint(problemSupport)
                .accessDeniedHandler(problemSupport)
            .and()
            .headers()
                .contentSecurityPolicy("default-src 'self'; frame-src 'self' data:; script-src 'self' 'unsafe-inline' 'unsafe-eval' https://storage.googleapis.com; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:")
                .and()
                .referrerPolicy(ReferrerPolicyServerHttpHeadersWriter.ReferrerPolicy.STRICT_ORIGIN_WHEN_CROSS_ORIGIN)
                .and()
                .featurePolicy("geolocation 'none'; midi 'none'; sync-xhr 'none'; microphone 'none'; camera 'none'; magnetometer 'none'; gyroscope 'none'; speaker 'none'; fullscreen 'self'; payment 'none'")
            .and()
                .frameOptions().disable()
            .and()
            .authorizeExchange()
                .pathMatchers("/").permitAll()
                .pathMatchers("/*.*").permitAll()
                .pathMatchers("/api/auth-info").permitAll()
                .pathMatchers("/api/**").authenticated()
                .pathMatchers("/management/health").permitAll()
                .pathMatchers("/management/info").permitAll()
                .pathMatchers("/management/prometheus").permitAll()
                .pathMatchers("/management/**").hasAuthority(AuthoritiesConstants.ADMIN)
            .and()
                .oauth2Login()
                //.authenticationSuccessHandler(this::onAuthenticationSuccess)
                //.authenticationFailureHandler(this::onAuthenticationError)
            .and()
                .oauth2ResourceServer()
                .jwt()
                .jwtAuthenticationConverter(grantedAuthoritiesExtractor())
            .and()
                .and()
                .oauth2Client();
        return http.build();
        // @formatter:on
    }

    Converter<Jwt, Mono<AbstractAuthenticationToken>> grantedAuthoritiesExtractor() {
        JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
        jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(new JwtAuthorityExtractor());
        return new ReactiveJwtAuthenticationConverterAdapter(jwtAuthenticationConverter);
    }

    /**
     * Map authorities from "groups" or "roles" claim in ID Token.
     *
     * @return a {@link ReactiveOAuth2UserService} that has the groups from the IdP.
     */
    @Bean
    public ReactiveOAuth2UserService<OidcUserRequest, OidcUser> oidcUserService() {
        final OidcReactiveOAuth2UserService delegate = new OidcReactiveOAuth2UserService();

        return (userRequest) -> {
            // Delegate to the default implementation for loading a user
            return delegate.loadUser(userRequest).map(user -> {
                Set<GrantedAuthority> mappedAuthorities = new HashSet<>();

                user.getAuthorities().forEach(authority -> {
                    if (authority instanceof OidcUserAuthority) {
                        OidcUserAuthority oidcUserAuthority = (OidcUserAuthority) authority;
                        mappedAuthorities.addAll(SecurityUtils.extractAuthorityFromClaims(oidcUserAuthority.getUserInfo().getClaims()));
                    }
                });

                return new DefaultOidcUser(mappedAuthorities, user.getIdToken(), user.getUserInfo());
            });
        };
    }

    @Bean
    ReactiveJwtDecoder jwtDecoder() {
        NimbusReactiveJwtDecoder jwtDecoder = (NimbusReactiveJwtDecoder)
            ReactiveJwtDecoders.fromOidcIssuerLocation(issuerUri);

        OAuth2TokenValidator<Jwt> audienceValidator = new AudienceValidator(jHipsterProperties.getSecurity().getOauth2().getAudience());
        OAuth2TokenValidator<Jwt> withIssuer = JwtValidators.createDefaultWithIssuer(issuerUri);
        OAuth2TokenValidator<Jwt> withAudience = new DelegatingOAuth2TokenValidator<>(withIssuer, audienceValidator);

        jwtDecoder.setJwtValidator(withAudience);

        return jwtDecoder;
    }

    private Mono<Void> onAuthenticationError(WebFilterExchange exchange, AuthenticationException e) {
        exchange.getExchange().getResponse().setStatusCode(HttpStatus.UNAUTHORIZED);
            return exchange.getExchange()
                .getFormData()
                .map(data -> data.getFirst("username"))
                .filter(login -> !Constants.ANONYMOUS_USER.equals(login))
                .flatMap(login -> auditEventService.saveAuthenticationError(login, e))
                .then();
    }

    private Mono<Void> onAuthenticationSuccess(WebFilterExchange exchange, Authentication authentication) {
        exchange.getExchange().getResponse().setStatusCode(HttpStatus.OK);
            return Mono.just(authentication.getPrincipal())
                .filter(principal -> principal instanceof OAuth2AuthenticationToken)
                .map(principal -> ((OAuth2AuthenticationToken) principal).getName())
                .filter(login -> !Constants.ANONYMOUS_USER.equals(login))
                .flatMap(auditEventService::saveAuthenticationSuccess)
                .then();
    }
}
