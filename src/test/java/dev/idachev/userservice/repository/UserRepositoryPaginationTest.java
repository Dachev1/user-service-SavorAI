package dev.idachev.userservice.repository;

import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.orm.jpa.DataJpaTest;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Pageable;
import org.springframework.data.domain.Sort;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;

import java.time.LocalDateTime;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

@DataJpaTest
class UserRepositoryPaginationTest {

    @Autowired
    private UserRepository userRepository;
    
    private final BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
    private final List<User> testUsers = new ArrayList<>();
    private final int TOTAL_USERS = 25;

    @BeforeEach
    void setUp() throws InterruptedException {
        // Create a set of test users with predictable ordering
        for (int i = 0; i < TOTAL_USERS; i++) {
            String username = String.format("user%02d", i);
            String email = String.format("user%02d@example.com", i);
            
            User user = new User();
            user.setUsername(username);
            user.setEmail(email);
            user.setPassword(passwordEncoder.encode("Password123!"));
            user.setRole(i % 5 == 0 ? Role.ADMIN : Role.USER); // Make every 5th user an admin
            user.setEnabled(i % 4 != 0); // Disable every 4th user
            user.setBanned(i % 10 == 0); // Ban every 10th user
            
            // Add varied creation dates - going backward from now
            // Add small sleep to ensure distinct timestamps if needed
            Thread.sleep(2); 
            user.setCreatedOn(LocalDateTime.now().minusDays(i).truncatedTo(ChronoUnit.MILLIS)); // Truncate for consistency
            
            User saved = userRepository.save(user);
            testUsers.add(saved);
        }
    }

    @AfterEach
    void tearDown() {
        userRepository.deleteAll();
        testUsers.clear();
    }

    @Test
    @DisplayName("Should return correct page of users")
    void should_ReturnCorrectPageOfUsers() {
        // Given
        int pageSize = 5;
        int pageNumber = 0;
        Pageable pageable = PageRequest.of(pageNumber, pageSize);
        
        // When
        Page<User> result = userRepository.findAll(pageable);
        
        // Then
        assertThat(result).isNotNull();
        assertThat(result.getContent()).hasSize(pageSize);
        assertThat(result.getTotalElements()).isEqualTo(TOTAL_USERS);
        assertThat(result.getTotalPages()).isEqualTo((int) Math.ceil((double) TOTAL_USERS / pageSize));
        assertThat(result.getNumber()).isEqualTo(pageNumber);
    }
    
    @Test
    @DisplayName("Should sort users by username ascending")
    void should_SortUsersByUsername_Ascending() {
        // Given
        Pageable pageable = PageRequest.of(0, TOTAL_USERS, Sort.by(Sort.Direction.ASC, "username"));
        
        // When
        Page<User> result = userRepository.findAll(pageable);
        
        // Then
        assertThat(result).isNotNull();
        List<User> users = result.getContent();
        
        // Verify users are sorted by username ascending
        for (int i = 0; i < users.size() - 1; i++) {
            String currentUsername = users.get(i).getUsername();
            String nextUsername = users.get(i + 1).getUsername();
            assertThat(currentUsername.compareTo(nextUsername)).isLessThanOrEqualTo(0);
        }
    }
    
    @Test
    @DisplayName("Should sort users by creation date descending")
    void should_SortUsersByCreationDate_Descending() {
        // Given
        Pageable pageable = PageRequest.of(0, TOTAL_USERS, Sort.by(Sort.Direction.DESC, "createdOn"));
        
        // When
        Page<User> result = userRepository.findAll(pageable);
        
        // Then
        assertThat(result).isNotNull();
        List<User> users = result.getContent();
        
        // Verify users are sorted by creation date descending (newest first)
        for (int i = 0; i < users.size() - 1; i++) {
            LocalDateTime currentDate = users.get(i).getCreatedOn();
            LocalDateTime nextDate = users.get(i + 1).getCreatedOn();
            assertThat(currentDate).isAfterOrEqualTo(nextDate);
        }
    }
    
    @Test
    @DisplayName("Should find users by role")
    void should_FindUsersByRole() {
        // Given - Find admin users (every 5th user is admin)
        Role adminRole = Role.ADMIN;
        
        // When
        List<User> adminUsers = userRepository.findAll().stream()
                .filter(user -> user.getRole() == adminRole)
                .toList();
        
        // Then
        int expectedAdminCount = (int) Math.ceil((double) TOTAL_USERS / 5);
        assertThat(adminUsers).hasSize(expectedAdminCount);
        
        // Verify all returned users have ADMIN role
        adminUsers.forEach(user -> assertThat(user.getRole()).isEqualTo(Role.ADMIN));
    }
    
    @Test
    @DisplayName("Should find users by enabled status with pagination")
    void should_FindUsersByEnabledStatus_WithPagination() {
        // Given - every 4th user is disabled
        Pageable pageable = PageRequest.of(0, 10);
        
        // When - find enabled users
        List<User> enabledUsers = userRepository.findAll().stream()
                .filter(User::isEnabled)
                .limit(pageable.getPageSize())
                .toList();
        
        // Then - total count would be 75% of users as 1/4 are disabled
        int expectedEnabledCount = (int) (TOTAL_USERS * 0.75); 
        
        // Verify all returned users are enabled
        enabledUsers.forEach(user -> assertThat(user.isEnabled()).isTrue());
    }
    
    @Test
    @DisplayName("Should find users by banned status")
    void should_FindUsersByBannedStatus() {
        // Given - every 10th user is banned
        boolean bannedStatus = true;
        
        // When
        List<User> bannedUsers = userRepository.findAll().stream()
                .filter(User::isBanned)
                .toList();
        
        // Then
        int expectedBannedCount = (int) Math.ceil((double) TOTAL_USERS / 10);
        assertThat(bannedUsers).hasSize(expectedBannedCount);
        
        // Verify all returned users are banned
        bannedUsers.forEach(user -> assertThat(user.isBanned()).isTrue());
    }
    
    @Test
    @DisplayName("Should find users by email containing string")
    void should_FindUsersByEmailContaining() {
        // Given
        String emailPattern = "user0";
        
        // When
        List<User> matchingUsers = userRepository.findAll().stream()
                .filter(user -> user.getEmail().contains(emailPattern))
                .toList();
        
        // Then - should find user00 through user09
        assertThat(matchingUsers).hasSize(10);
        
        // Verify all returned users have email matching the pattern
        matchingUsers.forEach(user -> 
            assertThat(user.getEmail()).contains(emailPattern)
        );
    }
    
    @Test
    @DisplayName("Should count users by role")
    void should_CountUsersByRole() {
        // Given - Every 5th user is admin
        int expectedAdminCount = (int) Math.ceil((double) TOTAL_USERS / 5);
        int expectedUserCount = TOTAL_USERS - expectedAdminCount;

        // When - Use specific repository count methods
        long actualAdminCount = userRepository.countByRole(Role.ADMIN);
        long actualUserCount = userRepository.countByRole(Role.USER);
        
        // Then
        assertThat(actualAdminCount).isEqualTo(expectedAdminCount);
        assertThat(actualUserCount).isEqualTo(expectedUserCount);
    }
    
    @Test
    @DisplayName("Should count users by enabled status")
    void should_CountUsersByEnabledStatus() {
        // Given - every 4th user is disabled
        int expectedDisabledCount = (int) Math.floor((double) TOTAL_USERS / 4);
        int expectedEnabledCount = TOTAL_USERS - expectedDisabledCount; 
        
        // When - Use specific repository count methods
        long actualEnabledCount = userRepository.countByEnabledTrue();
        // Assuming no countByEnabledFalse, calculate implicitly or add if exists
        long totalCount = userRepository.count();
        
        // Then 
        assertThat(actualEnabledCount).isEqualTo(expectedEnabledCount);
        assertThat(totalCount - actualEnabledCount).isEqualTo(expectedDisabledCount); // Verify disabled count implicitly
    }
    
    @Test
    @DisplayName("Should count users by banned status")
    void should_CountUsersByBannedStatus() {
        // Given - every 10th user is banned
        int expectedBannedCount = (int) Math.ceil((double) TOTAL_USERS / 10);
        int expectedNotBannedCount = TOTAL_USERS - expectedBannedCount;
        
        // When - Use specific repository count methods
        long actualBannedCount = userRepository.countByBannedTrue();
        long actualNotBannedCount = userRepository.countByBannedFalse();
        
        // Then
        assertThat(actualBannedCount).isEqualTo(expectedBannedCount);
        assertThat(actualNotBannedCount).isEqualTo(expectedNotBannedCount);
    }
    
    @Test
    @DisplayName("Should find users created after a specific date")
    void should_FindUsersCreatedAfterDate() {
        // Given - 25 users created over 25 days
        // Find users created within the last 15 days (expecting users 0-14)
        int expectedSize = 15;
        assertThat(testUsers.size()).isGreaterThanOrEqualTo(expectedSize); // Ensure we have enough users for test
        
        // Use the exact creation time of the user created 15 days ago as the cutoff
        // (Index 15 corresponds to the user created 15 days ago, since list is reversed)
        User boundaryUser = testUsers.get(15); 
        LocalDateTime cutoffDate = boundaryUser.getCreatedOn();
        
        // When - Use the specific repository method
        List<User> recentUsers = userRepository.findByCreatedOnAfter(cutoffDate);
        
        // Then
        assertThat(recentUsers).isNotNull();
        assertThat(recentUsers).hasSize(expectedSize);
        
        // Verify the users returned are indeed the most recent ones (users 0 to 14)
        List<UUID> expectedIds = testUsers.subList(0, expectedSize).stream().map(User::getId).collect(Collectors.toList());
        List<UUID> actualIds = recentUsers.stream().map(User::getId).collect(Collectors.toList());
        // Sort both lists by ID to ensure order doesn't matter for comparison
        Collections.sort(expectedIds);
        Collections.sort(actualIds);
        assertThat(actualIds).isEqualTo(expectedIds);
    }
} 