package dev.idachev.userservice.service;

import dev.idachev.userservice.repository.UserRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
public class UserDetailsService implements org.springframework.security.core.userdetails.UserDetailsService {

    private static final Logger logger = LoggerFactory.getLogger(UserDetailsService.class);
    private final UserRepository userRepository;

    @Autowired
    public UserDetailsService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    @Transactional(readOnly = true)
    public UserDetails loadUserByUsername(String userIdentifier) throws UsernameNotFoundException {
        logger.debug("Loading user by identifier: {}", userIdentifier);
        
        // First try by email, then by username if not found
        return userRepository.findByEmail(userIdentifier)
                .or(() -> {
                    logger.debug("User not found by email, trying by username: {}", userIdentifier);
                    return userRepository.findByUsername(userIdentifier);
                })
                .orElseThrow(() -> {
                    logger.warn("User not found with email or username: {}", userIdentifier);
                    return new UsernameNotFoundException("User not found with email or username: " + userIdentifier);
                });
    }
} 
