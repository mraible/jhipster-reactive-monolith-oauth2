package com.mycompany.myapp.service;

import com.mycompany.myapp.config.Constants;
import com.mycompany.myapp.domain.Authority;
import com.mycompany.myapp.domain.User;
import com.mycompany.myapp.repository.AuthorityRepository;
import com.mycompany.myapp.repository.UserRepository;
import com.mycompany.myapp.security.SecurityUtils;
import com.mycompany.myapp.service.dto.UserDTO;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.domain.Pageable;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Service;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Service class for managing users.
 */
@Service
public class UserService {

    private final Logger log = LoggerFactory.getLogger(UserService.class);

    private final UserRepository userRepository;

    private final AuthorityRepository authorityRepository;

    public UserService(UserRepository userRepository, AuthorityRepository authorityRepository) {
        this.userRepository = userRepository;
        this.authorityRepository = authorityRepository;
    }

    /**
     * Update basic information (first name, last name, email, language) for the current user.
     *
     * @param firstName first name of user.
     * @param lastName  last name of user.
     * @param email     email id of user.
     * @param langKey   language key.
     * @param imageUrl  image URL of user.
     */
    public Mono<Void> updateUser(String firstName, String lastName, String email, String langKey, String imageUrl) {
        return SecurityUtils.getCurrentUserLogin()
            .flatMap(userRepository::findOneByLogin)
            .flatMap(user -> {
                user.setFirstName(firstName);
                user.setLastName(lastName);
                if (email != null) {
                    user.setEmail(email.toLowerCase());
                }
                user.setLangKey(langKey);
                user.setImageUrl(imageUrl);
                return updateUser(user);
            })
            .doOnNext(user -> log.debug("Changed Information for User: {}", user))
            .then();
    }

    /**
     * Update all information for a specific user, and return the modified user.
     *
     * @param userDTO user to update.
     * @return updated user.
     */
    public Mono<UserDTO> updateUser(UserDTO userDTO) {
        return userRepository.findById(userDTO.getId())
            .flatMap(user -> {
                user.setLogin(userDTO.getLogin().toLowerCase());
                user.setFirstName(userDTO.getFirstName());
                user.setLastName(userDTO.getLastName());
                if (userDTO.getEmail() != null) {
                    user.setEmail(userDTO.getEmail().toLowerCase());
                }
                user.setImageUrl(userDTO.getImageUrl());
                user.setActivated(userDTO.isActivated());
                user.setLangKey(userDTO.getLangKey());
                Set<Authority> managedAuthorities = user.getAuthorities();
                managedAuthorities.clear();
                return Flux.fromIterable(userDTO.getAuthorities())
                    .flatMap(authorityRepository::findById)
                    .map(managedAuthorities::add)
                    .then(Mono.just(user));
            })
            .flatMap(this::updateUser)
            .doOnNext(user -> log.debug("Changed Information for User: {}", user))
            .map(UserDTO::new);
    }

    private Mono<User> updateUser(User user) {
        return SecurityUtils.getCurrentUserLogin()
            .switchIfEmpty(Mono.just(Constants.SYSTEM_ACCOUNT))
            .flatMap(login -> {
                user.setLastModifiedBy(login);
                return userRepository.save(user);
            });
    }

    private Mono<User> createUser(User user) {
        return SecurityUtils.getCurrentUserLogin()
            .switchIfEmpty(Mono.just(Constants.SYSTEM_ACCOUNT))
            .flatMap(login -> {
                user.setCreatedBy(login);
                user.setLastModifiedBy(login);
                return userRepository.save(user);
            });
    }

    public Mono<Void> deleteUser(String login) {
        return userRepository.findOneByLogin(login)
            .flatMap(user -> userRepository.delete(user).thenReturn(user))
            .doOnNext(user -> log.debug("Deleted User: {}", user))
            .then();
    }

    public Flux<UserDTO> getAllManagedUsers(Pageable pageable) {
        return userRepository.findAllByLoginNot(pageable, Constants.ANONYMOUS_USER).map(UserDTO::new);
    }

    public Mono<Long> countManagedUsers() {
        return userRepository.countAllByLoginNot(Constants.ANONYMOUS_USER);
    }

    public Mono<User> getUserWithAuthoritiesByLogin(String login) {
        return userRepository.findOneByLogin(login);
    }

    public Mono<User> getUserWithAuthorities(String id) {
        return userRepository.findById(id);
    }

    public Mono<User> getUserWithAuthorities() {
        return SecurityUtils.getCurrentUserLogin().flatMap(userRepository::findOneByLogin);
    }

    /**
     * Gets a list of all the authorities.
     * @return a list of all the authorities.
     */
    public Flux<String> getAuthorities() {
        return authorityRepository.findAll().map(Authority::getName);
    }

    private User syncUserWithIdP(Map<String, Object> details, User user) {
        // save authorities in to sync user roles/groups between IdP and JHipster's local database
        // todo: figure out how to call getAuthorities() w/o blocking
        Collection<String> dbAuthorities = Collections.EMPTY_LIST; // getAuthorities();
        Collection<String> userAuthorities =
            user.getAuthorities().stream().map(Authority::getName).collect(Collectors.toList());
        for (String authority : userAuthorities) {
            if (!dbAuthorities.contains(authority)) {
                log.debug("Saving authority '{}' in local database", authority);
                Authority authorityToSave = new Authority();
                authorityToSave.setName(authority);
                authorityRepository.save(authorityToSave);
            }
        }
        // save account in to sync users between IdP and JHipster's local database
        // todo: make non-blocking
        /* Optional<User> existingUser = userRepository.findOneByLogin(user.getLogin());
        if (existingUser.isPresent()) {
            // if IdP sends last updated information, use it to determine if an update should happen
            if (details.get("updated_at") != null) {
                Instant dbModifiedDate = existingUser.get().getLastModifiedDate();
                Instant idpModifiedDate = new Date(Long.valueOf((Integer) details.get("updated_at"))).toInstant();
                if (idpModifiedDate.isAfter(dbModifiedDate)) {
                    log.debug("Updating user '{}' in local database", user.getLogin());
                    updateUser(user.getFirstName(), user.getLastName(), user.getEmail(),
                        user.getLangKey(), user.getImageUrl());
                }
                // no last updated info, blindly update
            } else {
                log.debug("Updating user '{}' in local database", user.getLogin());
                updateUser(user.getFirstName(), user.getLastName(), user.getEmail(),
                    user.getLangKey(), user.getImageUrl());
            }
        } else {
            log.debug("Saving user '{}' in local database", user.getLogin());
            userRepository.save(user);
        }*/
        return user;
    }

    /**
     * Returns the user from an OAuth 2.0 login or resource server with JWT.
     * Synchronizes the user in the local repository.
     *
     * @param authToken the authentication token.
     * @return the user from the authentication.
     */
    public UserDTO getUserFromAuthentication(AbstractAuthenticationToken authToken) {
        Map<String, Object> attributes;
        if (authToken instanceof OAuth2AuthenticationToken) {
            attributes = ((OAuth2AuthenticationToken) authToken).getPrincipal().getAttributes();
        } else if (authToken instanceof JwtAuthenticationToken) {
            attributes = ((JwtAuthenticationToken) authToken).getTokenAttributes();
        } else {
            throw new IllegalArgumentException("AuthenticationToken is not OAuth2 or JWT!");
        }
        User user = getUser(attributes);
        user.setAuthorities(authToken.getAuthorities().stream()
            .map(GrantedAuthority::getAuthority)
            .map(authority -> {
                Authority auth = new Authority();
                auth.setName(authority);
                return auth;
            })
            .collect(Collectors.toSet()));
        return new UserDTO(syncUserWithIdP(attributes, user));
    }

    private static User getUser(Map<String, Object> details) {
        User user = new User();
        // handle resource server JWT, where sub claim is email and uid is ID
        if (details.get("uid") != null) {
            user.setId((String) details.get("uid"));
            user.setLogin((String) details.get("sub"));
        } else {
            user.setId((String) details.get("sub"));
        }
        if (details.get("preferred_username") != null) {
            user.setLogin(((String) details.get("preferred_username")).toLowerCase());
        } else if (user.getLogin() == null) {
            user.setLogin(user.getId());
        }
        if (details.get("given_name") != null) {
            user.setFirstName((String) details.get("given_name"));
        }
        if (details.get("family_name") != null) {
            user.setLastName((String) details.get("family_name"));
        }
        if (details.get("email_verified") != null) {
            user.setActivated((Boolean) details.get("email_verified"));
        }
        if (details.get("email") != null) {
            user.setEmail(((String) details.get("email")).toLowerCase());
        } else {
            user.setEmail((String) details.get("sub"));
        }
        if (details.get("langKey") != null) {
            user.setLangKey((String) details.get("langKey"));
        } else if (details.get("locale") != null) {
            // trim off country code if it exists
            String locale = (String) details.get("locale");
            if (locale.contains("_")) {
                locale = locale.substring(0, locale.indexOf("_"));
            } else if (locale.contains("-")) {
                locale = locale.substring(0, locale.indexOf("-"));
            }
            user.setLangKey(locale.toLowerCase());
        } else {
            // set langKey to default if not specified by IdP
            user.setLangKey(Constants.DEFAULT_LANGUAGE);
        }
        if (details.get("picture") != null) {
            user.setImageUrl((String) details.get("picture"));
        }
        user.setActivated(true);
        return user;
    }
}
