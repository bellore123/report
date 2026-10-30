package com.cybershield.security;

import com.cybershield.model.User;
import com.cybershield.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import java.util.List;

/**
 * CustomUserDetailsService — tells Spring Security how to load a user from the database.
 *
 * Spring Security calls loadUserByUsername() during authentication.
 * We find the user in our DB, then wrap them in Spring's UserDetails format
 * with their role as a GrantedAuthority.
 */
@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {

    private final UserRepository userRepository;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username)
                .orElseThrow(() ->
                    new UsernameNotFoundException("User not found: " + username)
                );

        // Map our Role enum to Spring's GrantedAuthority
        // "ROLE_ADMIN", "ROLE_SERVER_ADMIN", "ROLE_VIEWER"
        return org.springframework.security.core.userdetails.User.builder()
                .username(user.getUsername())
                .password(user.getPasswordHash())     // BCrypt hash
                .authorities(List.of(
                    new SimpleGrantedAuthority("ROLE_" + user.getRole().name())
                ))
                .accountLocked(!user.isActive())       // locked = cannot login
                .build();
    }
}
