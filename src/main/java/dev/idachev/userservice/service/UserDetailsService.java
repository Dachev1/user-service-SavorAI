package dev.idachev.userservice.service;

import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.security.UserPrincipal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Slf4j
@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private final UserRepository userRepository;

    @Autowired
    public UserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String userIdentifier) throws UsernameNotFoundException {

        log.debug("Loading user by identifier: {}", userIdentifier);

        // First try by email, then by username if not found
        return userRepository.findByEmail(userIdentifier)
                .or(() -> {
                    log.debug("User not found by email, trying by username: {}", userIdentifier);
                    return userRepository.findByUsername(userIdentifier);
                })
                .map(UserPrincipal::new) // Wrap the User entity in UserPrincipal
                .orElseThrow(() -> {
                    log.warn("User not found with email or username: {}", userIdentifier);
                    return new UsernameNotFoundException("User not found with email or username: " + userIdentifier);
                });
    }
} 
