package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.OperationForbiddenException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.mapper.EntityMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.RegisterRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import dev.idachev.userservice.web.dto.ProfileUpdateRequest;
import dev.idachev.userservice.web.dto.UsernameAvailabilityResponse;
import dev.idachev.userservice.web.dto.UserStatsResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;
import org.mockito.ArgumentCaptor;

/**
 * Unit tests for {@link UserService}.
 */
@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class UserServiceUTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private CacheManager cacheManager;

    @Mock
    private PasswordEncoder passwordEncoder;

    @Mock
    private EmailService emailService;

    @Mock
    private TokenService tokenService;

    @Mock
    private VerificationService verificationService;

    @Mock
    private Cache usersCache;
    @Mock
    private Cache usernamesCache;
    @Mock
    private Cache userStatsCache;

    @InjectMocks
    private UserService userService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;
    private MockedStatic<EntityMapper> entityMapperMockedStatic;

    @BeforeEach
    void setUp() {
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
        entityMapperMockedStatic = Mockito.mockStatic(EntityMapper.class);
        when(cacheManager.getCache("users")).thenReturn(usersCache);
        when(cacheManager.getCache("usernames")).thenReturn(usernamesCache);
        when(cacheManager.getCache("userStats")).thenReturn(userStatsCache);
    }

    @AfterEach
    void tearDown() {
        dtoMapperMockedStatic.close();
        entityMapperMockedStatic.close();
    }

    @Nested
    @DisplayName("getUserById Tests")
    class GetUserByIdTests {

        @Test
        @DisplayName("Should return user when user exists")
        void getUserById_whenUserExists_shouldReturnUserResponse() {
            UUID userId = UUID.randomUUID();
            LocalDateTime now = LocalDateTime.now();
            User mockUser = User.builder()
                    .id(userId)
                    .username("testuser")
                    .password("password123")
                    .email("test@example.com")
                    .role(Role.USER)
                    .enabled(true)
                    .banned(false)
                    .createdOn(now)
                    .updatedOn(now)
                    .verificationToken(null)
                    .build();

            UserResponse expectedResponse = UserResponse.builder()
                    .id(userId)
                    .username("testuser")
                    .email("test@example.com")
                    .role(Role.USER.name())
                    .enabled(true)
                    .banned(false)
                    .createdOn(now)
                    .firstName(null)
                    .lastName(null)
                    .bio(null)
                    .verificationPending(false)
                    .lastLogin(null)
                    .build();

            when(userRepository.findById(userId)).thenReturn(Optional.of(mockUser));
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(mockUser)).thenReturn(expectedResponse);

            UserResponse actualResponse = userService.getUserById(userId);

            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getId()).isEqualTo(expectedResponse.getId());
            assertThat(actualResponse.getUsername()).isEqualTo(expectedResponse.getUsername());
            assertThat(actualResponse.getEmail()).isEqualTo(expectedResponse.getEmail());
            assertThat(actualResponse.getRole()).isEqualTo(expectedResponse.getRole());
            assertThat(actualResponse.isEnabled()).isEqualTo(expectedResponse.isEnabled());
            assertThat(actualResponse.isBanned()).isEqualTo(expectedResponse.isBanned());
            assertThat(actualResponse.getCreatedOn()).isEqualTo(expectedResponse.getCreatedOn());

            verify(userRepository, times(1)).findById(userId);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(mockUser), times(1));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void getUserById_whenUserDoesNotExist_shouldThrowResourceNotFoundException() {
            UUID userId = UUID.randomUUID();
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            assertThatThrownBy(() -> userService.getUserById(userId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + userId);

            verify(userRepository, times(1)).findById(userId);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    @Nested
    @DisplayName("registerUser Tests")
    class RegisterUserTests {

        @Test
        @DisplayName("Should register user successfully")
        void registerUser_whenValidRequest_shouldReturnSavedUser() {
            RegisterRequest request = new RegisterRequest("newuser", "new@example.com", "Password123!");
            String encodedPassword = "encodedPassword123";
            String verificationToken = "test-verification-token";

            // Prepare the user object expected to be created by the mapper
            User newUserMapped = User.builder()
                    .username(request.username())
                    .email(request.email())
                    .password(encodedPassword)
                    .verificationToken(verificationToken)
                    .role(Role.USER)
                    .enabled(false) // Default for new registration
                    .build();

            // Prepare the user object expected to be returned by save
            User savedUser = User.builder()
                    .id(UUID.randomUUID())
                    .username(request.username())
                    .email(request.email())
                    .password(encodedPassword)
                    .verificationToken(verificationToken)
                    .role(Role.USER)
                    .enabled(false)
                    .createdOn(LocalDateTime.now())
                    .updatedOn(LocalDateTime.now())
                    .build();

            // Mock dependencies
            when(passwordEncoder.encode(request.password())).thenReturn(encodedPassword);
            when(verificationService.generateVerificationToken()).thenReturn(verificationToken);

            // *** Mock the static EntityMapper call ***
            entityMapperMockedStatic.when(() -> EntityMapper.mapToNewUser(request, passwordEncoder, verificationToken))
                    .thenReturn(newUserMapped);

            // Mock the repository save call - ensure it's called with the mapped user
            when(userRepository.save(newUserMapped)).thenReturn(savedUser);

            // When
            User result = userService.registerUser(request);

            // Then
            assertThat(result).isNotNull(); // Check if null (this was the original failure point)
            assertThat(result).isEqualTo(savedUser);
            assertThat(result.getId()).isEqualTo(savedUser.getId());
            assertThat(result.getUsername()).isEqualTo(request.username());
            assertThat(result.getEmail()).isEqualTo(request.email());
            assertThat(result.getPassword()).isEqualTo(encodedPassword);
            assertThat(result.getVerificationToken()).isEqualTo(verificationToken);
            assertThat(result.isEnabled()).isFalse();
            assertThat(result.getRole()).isEqualTo(Role.USER);

            // Verify interactions
            verify(verificationService, times(1)).generateVerificationToken();
            entityMapperMockedStatic.verify(() -> EntityMapper.mapToNewUser(request, passwordEncoder, verificationToken), times(1));
            verify(userRepository, times(1)).save(newUserMapped); // Verify save was called with the correct object
        }
    }

    @Nested
    @DisplayName("getAllUsers Tests")
    class GetAllUsersTests {

        @Test
        @DisplayName("Should return list of UserResponse when users exist")
        void getAllUsers_whenUsersExist_shouldReturnUserResponseList() {
            // Given
            UUID userId1 = UUID.randomUUID();
            UUID userId2 = UUID.randomUUID();
            LocalDateTime now = LocalDateTime.now();

            User user1 = User.builder().id(userId1).username("user1").email("user1@test.com").role(Role.USER).enabled(true).createdOn(now).updatedOn(now).build();
            User user2 = User.builder().id(userId2).username("user2").email("user2@test.com").role(Role.ADMIN).enabled(true).createdOn(now).updatedOn(now).build();
            List<User> users = List.of(user1, user2);

            UserResponse response1 = UserResponse.builder().id(userId1).username("user1").email("user1@test.com").role(Role.USER.name()).enabled(true).createdOn(now).build();
            UserResponse response2 = UserResponse.builder().id(userId2).username("user2").email("user2@test.com").role(Role.ADMIN.name()).enabled(true).createdOn(now).build();
            List<UserResponse> expectedResponses = List.of(response1, response2);

            // Mock repository call
            when(userRepository.findAll()).thenReturn(users);

            // Mock static mapper call for each user
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(user1)).thenReturn(response1);
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(user2)).thenReturn(response2);

            // When
            List<UserResponse> actualResponses = userService.getAllUsers();

            // Then
            assertThat(actualResponses)
                    .isNotNull()
                    .hasSize(2)
                    .containsExactlyInAnyOrderElementsOf(expectedResponses);

            // Verify interactions
            verify(userRepository, times(1)).findAll();
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(user1), times(1));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(user2), times(1));
        }

        @Test
        @DisplayName("Should return empty list when no users exist")
        void getAllUsers_whenNoUsersExist_shouldReturnEmptyList() {
            // Given
            when(userRepository.findAll()).thenReturn(List.of());

            // When
            List<UserResponse> actualResponses = userService.getAllUsers();

            // Then
            assertThat(actualResponses)
                    .isNotNull()
                    .isEmpty();

            // Verify interactions
            verify(userRepository, times(1)).findAll();
            // Ensure mapper is never called
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    @Nested
    @DisplayName("updateUserRole Tests")
    class UpdateUserRoleTests {

        private User existingUser;
        private UUID userId;

        @BeforeEach
        void setupUser() {
            userId = UUID.randomUUID();
            existingUser = User.builder()
                    .id(userId)
                    .username("existingUser")
                    .email("existing@test.com")
                    .role(Role.USER)
                    .enabled(true)
                    .build();
        }

        // Helper method to mock SecurityContext to control isCurrentUser outcome
        // This is a simplified approach. For complex security testing, consider spring-security-test utils.
        private void mockSecurityContext(boolean isCurrentUserResult) {
            // We can spy on the service to mock the isCurrentUser check directly for simplicity
            // Or use SecurityContextHolder mocking (more complex)
            // For now, let's assume we can control this via a direct mock/spy if needed.
            // We will mock the behavior directly in the test for now.
        }

        @Test
        @DisplayName("Should update user role successfully when user exists and not self-update")
        void updateUserRole_whenUserExistsAndNotSelfUpdate_shouldUpdateRoleAndInvalidateTokens() {
            // Given
            Role newRole = Role.ADMIN;
            User updatedUser = existingUser.toBuilder().role(newRole).build(); // User after role update
            User savedUser = updatedUser; // Assume save returns the same object or mock accordingly

            // Mock the check: assume the user being updated is NOT the current user
            // Instead of complex SecurityContext mocking, we can sometimes spy the service if needed.
            // Here, we rely on the `findById` mock returning a user whose ID won't match the *implicit* current user.
            // A better approach might involve mocking SecurityContextHolder or refactoring isCurrentUser.
            // For this test, we assume the check passes implicitly by not throwing.

            when(userRepository.findById(userId)).thenReturn(Optional.of(existingUser));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> invocation.getArgument(0)); // Return the saved user
            // No exception expected from tokenService.invalidateUserTokens
            doNothing().when(tokenService).invalidateUserTokens(userId);
            // Mock cache eviction (simplified: assume evictCollectionCaches works if called)
            // If evictCollectionCaches was public/protected or we spied, we could verify it.
            // Alternatively, mock CacheManager interactions if needed.

            // When
            User result = userService.updateUserRole(userId, newRole);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(userId);
            assertThat(result.getRole()).isEqualTo(newRole);

            // Verify interactions
            verify(userRepository, times(1)).findById(userId);
            verify(userRepository, times(1)).save(argThat(user -> user.getId().equals(userId) && user.getRole().equals(newRole)));
            verify(tokenService, times(1)).invalidateUserTokens(userId);
            // Verify cache eviction happened (indirectly, or mock CacheManager)
            // Example: if evictCollectionCaches clears specific caches:
            // Cache usersCache = mock(Cache.class);
            // when(cacheManager.getCache("users")).thenReturn(usersCache);
            // verify(usersCache, times(1)).clear(); // Adjust based on actual evictCollectionCaches implementation
        }

        @Test
        @DisplayName("Should throw OperationForbiddenException when admin tries to change own role")
        void updateUserRole_whenAdminChangesOwnRole_shouldThrowOperationForbiddenException() {
            // Given
            Role newRole = Role.USER;
            UUID currentUserId = userId; // Make the target user ID the same as the 'current' user

            // Mocking the isCurrentUser check to return true
            // We need a way to simulate this. Spying the service is one way:
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(true).when(spiedUserService).isCurrentUser(currentUserId);
            // Note: This requires userService field NOT to be final if using @InjectMocks
            // Alternatively, mock SecurityContextHolder (more involved setup)

            // When & Then
            // Use the spied service instance for the call
            assertThatThrownBy(() -> spiedUserService.updateUserRole(currentUserId, newRole))
                    .isInstanceOf(OperationForbiddenException.class)
                    .hasMessageContaining("Admins cannot change their own role");

            // Verify no save or token invalidation occurred
            verify(userRepository, never()).findById(any()); // isCurrentUser check happens before findById
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void updateUserRole_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            Role newRole = Role.ADMIN;
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            // Mocking the isCurrentUser check to return false (so it proceeds to findById)
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).isCurrentUser(userId);

            // When & Then
            assertThatThrownBy(() -> spiedUserService.updateUserRole(userId, newRole))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + userId);

            // Verify findById was called, but not save or invalidate
            verify(userRepository, times(1)).findById(userId);
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
        }

        // Add test for case where tokenService.invalidateUserTokens throws an exception? (Depends on desired behavior)
    }

    @Nested
    @DisplayName("toggleUserBan Tests")
    class ToggleUserBanTests {

        private User targetUser;
        private UUID targetUserId;

        @BeforeEach
        void setupTargetUser() {
            targetUserId = UUID.randomUUID();
            // Start with an unbanned user by default for most tests
            targetUser = User.builder()
                    .id(targetUserId)
                    .username("targetUser")
                    .email("target@test.com")
                    .role(Role.USER)
                    .enabled(true)
                    .banned(false) // Default: not banned
                    .build();
        }

        @Test
        @DisplayName("Should ban user successfully when user is not banned and not self-action")
        void toggleUserBan_whenUserNotBannedAndNotSelf_shouldBanUserAndInvalidateTokens() {
            // Given
            targetUser = targetUser.toBuilder().banned(false).build(); // Ensure user starts unbanned
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).isCurrentUser(targetUserId); // Assume not self-action

            when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User userToSave = invocation.getArgument(0);
                // Simulate the save setting the banned status
                return userToSave.toBuilder().banned(true).build();
            });
            doNothing().when(tokenService).invalidateUserTokens(targetUserId);
            // Mock cache eviction if needed

            // When
            User result = spiedUserService.toggleUserBan(targetUserId);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(targetUserId);
            assertThat(result.isBanned()).isTrue(); // Assert user is now banned

            // Verify interactions
            verify(userRepository, times(1)).findById(targetUserId);
            verify(userRepository, times(1)).save(argThat(user -> user.getId().equals(targetUserId) && user.isBanned()));
            verify(tokenService, times(1)).invalidateUserTokens(targetUserId); // Tokens should be invalidated when banning
            // Verify cache eviction
        }

        @Test
        @DisplayName("Should unban user successfully when user is banned and not self-action")
        void toggleUserBan_whenUserBannedAndNotSelf_shouldUnbanUser() {
            // Given
            targetUser = targetUser.toBuilder().banned(true).build(); // Ensure user starts banned
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).isCurrentUser(targetUserId); // Assume not self-action

            when(userRepository.findById(targetUserId)).thenReturn(Optional.of(targetUser));
            when(userRepository.save(any(User.class))).thenAnswer(invocation -> {
                User userToSave = invocation.getArgument(0);
                // Simulate the save setting the banned status
                return userToSave.toBuilder().banned(false).build();
            });
            // No need to mock tokenService.invalidateUserTokens as it shouldn't be called
            // Mock cache eviction if needed

            // When
            User result = spiedUserService.toggleUserBan(targetUserId);

            // Then
            assertThat(result).isNotNull();
            assertThat(result.getId()).isEqualTo(targetUserId);
            assertThat(result.isBanned()).isFalse(); // Assert user is now unbanned

            // Verify interactions
            verify(userRepository, times(1)).findById(targetUserId);
            verify(userRepository, times(1)).save(argThat(user -> user.getId().equals(targetUserId) && !user.isBanned()));
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class)); // Tokens should NOT be invalidated when unbanning
            // Verify cache eviction
        }

        @Test
        @DisplayName("Should throw OperationForbiddenException when admin tries to ban self")
        void toggleUserBan_whenAdminBansSelf_shouldThrowOperationForbiddenException() {
            // Given
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(true).when(spiedUserService).isCurrentUser(targetUserId); // Simulate self-action

            // When & Then
            assertThatThrownBy(() -> spiedUserService.toggleUserBan(targetUserId))
                    .isInstanceOf(OperationForbiddenException.class)
                    .hasMessageContaining("Admins cannot ban themselves");

            // Verify no repository or token service interaction
            verify(userRepository, never()).findById(any());
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void toggleUserBan_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).isCurrentUser(targetUserId); // Not self-action
            when(userRepository.findById(targetUserId)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> spiedUserService.toggleUserBan(targetUserId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + targetUserId);

            // Verify findById was called, but nothing else
            verify(userRepository, times(1)).findById(targetUserId);
            verify(userRepository, never()).save(any(User.class));
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
        }
    }

    @Nested
    @DisplayName("getUserByUsername Tests")
    class GetUserByUsernameTests {

        @Test
        @DisplayName("Should return UserResponse when user exists")
        void getUserByUsername_whenUserExists_shouldReturnUserResponse() {
            // Given
            String username = "testuser";
            UUID userId = UUID.randomUUID();
            User mockUser = User.builder().id(userId).username(username).email("test@test.com").build();
            UserResponse expectedResponse = UserResponse.builder().id(userId).username(username).email("test@test.com").build();

            when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(mockUser)).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = userService.getUserByUsername(username);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getUsername()).isEqualTo(username);
            verify(userRepository, times(1)).findByUsername(username);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(mockUser), times(1));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void getUserByUsername_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            String username = "nonexistent";
            when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> userService.getUserByUsername(username))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with username: " + username);

            verify(userRepository, times(1)).findByUsername(username);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    @Nested
    @DisplayName("getUserByEmail Tests")
    class GetUserByEmailTests {

        @Test
        @DisplayName("Should return UserResponse when user exists")
        void getUserByEmail_whenUserExists_shouldReturnUserResponse() {
            // Given
            String email = "test@example.com";
            UUID userId = UUID.randomUUID();
            User mockUser = User.builder().id(userId).username("testuser").email(email).build();
            UserResponse expectedResponse = UserResponse.builder().id(userId).username("testuser").email(email).build();

            when(userRepository.findByEmail(email)).thenReturn(Optional.of(mockUser));
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(mockUser)).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = userService.getUserByEmail(email);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getEmail()).isEqualTo(email);
            verify(userRepository, times(1)).findByEmail(email);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(mockUser), times(1));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void getUserByEmail_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            String email = "nonexistent@example.com";
            when(userRepository.findByEmail(email)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> userService.getUserByEmail(email))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with email: " + email);

            verify(userRepository, times(1)).findByEmail(email);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    @Nested
    @DisplayName("existsByUsername Tests")
    class ExistsByUsernameTests {

        @Test
        @DisplayName("Should return true when username exists")
        void existsByUsername_whenUsernameExists_shouldReturnTrue() {
            // Given
            String username = "existinguser";
            when(userRepository.existsByUsername(username)).thenReturn(true);

            // When
            boolean exists = userService.existsByUsername(username);

            // Then
            assertThat(exists).isTrue();
            verify(userRepository, times(1)).existsByUsername(username);
        }

        @Test
        @DisplayName("Should return false when username does not exist")
        void existsByUsername_whenUsernameDoesNotExist_shouldReturnFalse() {
            // Given
            String username = "nonexistentuser";
            when(userRepository.existsByUsername(username)).thenReturn(false);

            // When
            boolean exists = userService.existsByUsername(username);

            // Then
            assertThat(exists).isFalse();
            verify(userRepository, times(1)).existsByUsername(username);
        }
    }

    @Nested
    @DisplayName("findByUsername Tests (returns User entity)")
    class FindByUsernameTests {

        @Test
        @DisplayName("Should return User entity when user exists")
        void findByUsername_whenUserExists_shouldReturnUserEntity() {
            // Given
            String username = "findme";
            User mockUser = User.builder().id(UUID.randomUUID()).username(username).build();
            when(userRepository.findByUsername(username)).thenReturn(Optional.of(mockUser));

            // When
            User actualUser = userService.findByUsername(username);

            // Then
            assertThat(actualUser).isNotNull();
            assertThat(actualUser.getUsername()).isEqualTo(username);
            assertThat(actualUser).isEqualTo(mockUser);
            verify(userRepository, times(1)).findByUsername(username);
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void findByUsername_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            String username = "cantfindme";
            when(userRepository.findByUsername(username)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> userService.findByUsername(username))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with username: " + username);

            verify(userRepository, times(1)).findByUsername(username);
        }
    }

    @Nested
    @DisplayName("updateProfile Tests")
    class UpdateProfileTests {

        private final String currentUsername = "currentuser";
        private final String currentUserEmail = "current@test.com";
        private User currentUser;

        @BeforeEach
        void setupCurrentUser() {
            currentUser = User.builder()
                    .id(UUID.randomUUID())
                    .username(currentUsername)
                    .email(currentUserEmail)
                    .password("encodedPassword")
                    .role(Role.USER)
                    .enabled(true)
                    .build();
        }

        @Test
        @DisplayName("Should update username successfully when new username is valid and available")
        void updateProfile_whenNewUsernameIsValidAndAvailable_shouldUpdateAndEvictCaches() {
            // Given
            String newUsername = "newusername";
            ProfileUpdateRequest request = ProfileUpdateRequest.builder()
                    .username(newUsername)
                    .currentPassword("ignoredInThisMethod") // Assuming password check happens elsewhere
                    .build();

            UserResponse expectedResponse = UserResponse.builder()
                    .id(currentUser.getId())
                    .username(newUsername)
                    .email(currentUserEmail)
                    // ... other fields ...
                    .build();

            // Mock finding the current user
            when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(currentUser));
            // Mock username availability check (new username doesn't exist)
            when(userRepository.existsByUsername(newUsername)).thenReturn(false);
            // Mock saving the user (use ArgumentCaptor to check the saved state)
            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            when(userRepository.save(userCaptor.capture())).thenAnswer(inv -> inv.getArgument(0));
            // Mock the DTO mapping
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(any(User.class))).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = userService.updateProfile(currentUsername, request);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getUsername()).isEqualTo(newUsername);

            // Verify the captured user passed to save()
            User savedUser = userCaptor.getValue();
            assertThat(savedUser.getUsername()).isEqualTo(newUsername);
            assertThat(savedUser.getId()).isEqualTo(currentUser.getId());

            // Verify interactions
            verify(userRepository, times(1)).findByUsername(currentUsername);
            verify(userRepository, times(1)).existsByUsername(newUsername);
            verify(userRepository, times(1)).save(any(User.class));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(savedUser), times(1));

            // Verify specific cache evictions because username changed
            verify(usersCache, times(1)).evict("'username_'" + currentUsername);
            verify(usersCache, times(1)).evict("'username_'" + newUsername);
            verify(usersCache, times(1)).evict(currentUser.getId());
            verify(usernamesCache, times(1)).evict(currentUser.getId());
            // Verify collection cache eviction
            verify(usersCache, times(1)).evict("'allUsers'"); // Corrected verification
            verify(usernamesCache, times(1)).clear(); // From evictCollectionCaches (updated verification)
        }

        @Test
        @DisplayName("Should not update username or evict caches when new username is same as current")
        void updateProfile_whenNewUsernameIsSame_shouldNotUpdateOrEvict() {
            // Given
            String sameUsername = currentUsername;
            ProfileUpdateRequest request = ProfileUpdateRequest.builder()
                    .username(sameUsername)
                    .currentPassword("ignored")
                    .build();

             UserResponse expectedResponse = UserResponse.builder()
                    .id(currentUser.getId())
                    .username(currentUsername)
                    .email(currentUserEmail)
                    // ... other fields ...
                    .build();

            when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(currentUser));
            // Assume save might still be called even if no change, depending on implementation.
            // If save is conditional, use verify(..., never()).save(...)
            when(userRepository.save(any(User.class))).thenReturn(currentUser);
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(currentUser)).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = userService.updateProfile(currentUsername, request);

            // Then
            assertThat(actualResponse).isNotNull();
            assertThat(actualResponse.getUsername()).isEqualTo(currentUsername);

            // Verify interactions
            verify(userRepository, times(1)).findByUsername(currentUsername);
            verify(userRepository, never()).existsByUsername(anyString()); // Availability check skipped
            verify(userRepository, times(1)).save(currentUser); // Verify save was called (or never() if conditional)
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(currentUser), times(1));

            // Verify NO specific cache evictions happened for username change
            verify(usersCache, never()).evict(anyString());
            verify(usersCache, never()).evict(any(UUID.class));
            verify(usernamesCache, never()).evict(any(UUID.class));
            verify(usersCache, never()).clear();
            verify(usernamesCache, never()).clear();
        }

        @Test
        @DisplayName("Should throw IllegalArgumentException when new username is already taken")
        void updateProfile_whenNewUsernameIsTaken_shouldThrowIllegalArgumentException() {
            // Given
            String takenUsername = "takenuser";
            ProfileUpdateRequest request = ProfileUpdateRequest.builder()
                    .username(takenUsername)
                    .currentPassword("ignored")
                    .build();

            when(userRepository.findByUsername(currentUsername)).thenReturn(Optional.of(currentUser));
            // Mock username availability check (new username DOES exist)
            when(userRepository.existsByUsername(takenUsername)).thenReturn(true);

            // When & Then
            assertThatThrownBy(() -> userService.updateProfile(currentUsername, request))
                    .isInstanceOf(IllegalArgumentException.class)
                    .hasMessageContaining("Username is already taken");

            // Verify interactions
            verify(userRepository, times(1)).findByUsername(currentUsername);
            verify(userRepository, times(1)).existsByUsername(takenUsername);
            verify(userRepository, never()).save(any(User.class)); // Save should not be called
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());

            // Verify no cache evictions happened
            verify(usersCache, never()).evict(any());
            verify(usernamesCache, never()).evict(any());
             verify(usersCache, never()).clear();
            verify(usernamesCache, never()).clear();
        }

         @Test
        @DisplayName("Should throw ResourceNotFoundException when current user cannot be found")
        void updateProfile_whenCurrentUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            String nonExistentUsername = "ghost";
             ProfileUpdateRequest request = ProfileUpdateRequest.builder()
                    .username("newname")
                    .currentPassword("ignored")
                    .build();

            when(userRepository.findByUsername(nonExistentUsername)).thenReturn(Optional.empty());

            // When & Then
             assertThatThrownBy(() -> userService.updateProfile(nonExistentUsername, request))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with username: " + nonExistentUsername);

            // Verify interactions
            verify(userRepository, times(1)).findByUsername(nonExistentUsername);
            verify(userRepository, never()).existsByUsername(anyString());
            verify(userRepository, never()).save(any(User.class));
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    @Nested
    @DisplayName("checkUsernameAvailability Tests")
    class CheckUsernameAvailabilityTests {

        @Test
        @DisplayName("Should return available=true when username does not exist")
        void checkUsernameAvailability_whenUsernameDoesNotExist_shouldReturnAvailableTrue() {
            // Given
            String availableUsername = "available_user";
            // Mock existsByUsername to return false
            // Use spy to test the call to the service's own existsByUsername method
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).existsByUsername(availableUsername);

            // When
            UsernameAvailabilityResponse response = spiedUserService.checkUsernameAvailability(availableUsername);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.isAvailable()).isTrue();
            assertThat(response.getUsername()).isEqualTo(availableUsername);
            assertThat(response.getMessage()).isEqualTo("Username is available");

            // Verify that the internal existsByUsername was called
            verify(spiedUserService, times(1)).existsByUsername(availableUsername);
        }

        @Test
        @DisplayName("Should return available=false when username exists")
        void checkUsernameAvailability_whenUsernameExists_shouldReturnAvailableFalse() {
            // Given
            String takenUsername = "taken_user";
            // Mock existsByUsername to return true
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(true).when(spiedUserService).existsByUsername(takenUsername);

            // When
            UsernameAvailabilityResponse response = spiedUserService.checkUsernameAvailability(takenUsername);

            // Then
            assertThat(response).isNotNull();
            assertThat(response.isAvailable()).isFalse();
            assertThat(response.getUsername()).isEqualTo(takenUsername);
            assertThat(response.getMessage()).isEqualTo("Username is already taken");

            // Verify that the internal existsByUsername was called
            verify(spiedUserService, times(1)).existsByUsername(takenUsername);
        }
    }

    @Nested
    @DisplayName("deleteUser Tests")
    class DeleteUserTests {
        private final UUID USER_ID_TO_DELETE = UUID.randomUUID();
        private User userToDelete;

        @BeforeEach
        void setUp() {
            userToDelete = User.builder().id(USER_ID_TO_DELETE).username("toDelete").build();
            // Mock caches needed for evictCollectionCaches
            when(cacheManager.getCache("users")).thenReturn(usersCache);
            when(cacheManager.getCache("usernames")).thenReturn(usernamesCache);
            when(cacheManager.getCache("userStats")).thenReturn(userStatsCache);
        }

        @Test
        @DisplayName("Should delete user successfully when not self-action and user exists")
        void deleteUser_whenNotSelfActionAndUserExists_shouldInvalidateTokensAndDelete() {
            // Given
            when(userRepository.findById(USER_ID_TO_DELETE)).thenReturn(Optional.of(userToDelete));
            doNothing().when(tokenService).invalidateUserTokens(USER_ID_TO_DELETE);
            doNothing().when(userRepository).delete(userToDelete);

            // When
            userService.deleteUser(USER_ID_TO_DELETE);

            // Then
            verify(tokenService).invalidateUserTokens(USER_ID_TO_DELETE);
            verify(userRepository).delete(userToDelete);
            // Verify cache evictions called by evictCollectionCaches
            verify(usersCache).evict("'allUsers'");
            verify(userStatsCache).clear();
            verify(usernamesCache).clear();
        }

        @Test
        @DisplayName("Should throw OperationForbiddenException when admin tries to delete self")
        void deleteUser_whenSelfAction_shouldThrowOperationForbiddenException() {
            // Given
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(true).when(spiedUserService).isCurrentUser(USER_ID_TO_DELETE); // Simulate self-action

            // When & Then
            assertThatThrownBy(() -> spiedUserService.deleteUser(USER_ID_TO_DELETE))
                    .isInstanceOf(OperationForbiddenException.class)
                    .hasMessageContaining("Admins cannot delete themselves");

            // Verify no other actions taken
            verify(userRepository, never()).findById(any());
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
            verify(userRepository, never()).delete(any(User.class));
            verify(usersCache, never()).clear();
            verify(usernamesCache, never()).clear();
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void deleteUser_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            UserService spiedUserService = Mockito.spy(userService);
            doReturn(false).when(spiedUserService).isCurrentUser(USER_ID_TO_DELETE); // Not self-action
            when(userRepository.findById(USER_ID_TO_DELETE)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> spiedUserService.deleteUser(USER_ID_TO_DELETE))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + USER_ID_TO_DELETE);

            // Verify only findById was attempted after the self-check
            verify(spiedUserService, times(1)).isCurrentUser(USER_ID_TO_DELETE);
            verify(userRepository, times(1)).findById(USER_ID_TO_DELETE);
            verify(tokenService, never()).invalidateUserTokens(any(UUID.class));
            verify(userRepository, never()).delete(any(User.class));
            verify(usersCache, never()).clear();
            verify(usernamesCache, never()).clear();
        }

        // Test case for when tokenService.invalidateUserTokens throws an exception?
    }

    @Nested
    @DisplayName("getUsernameById Tests")
    class GetUsernameByIdTests {

        @Test
        @DisplayName("Should return username when user exists")
        void getUsernameById_whenUserExists_shouldReturnUsername() {
            // Given
            UUID userId = UUID.randomUUID();
            String expectedUsername = "found_user";
            when(userRepository.findUsernameById(userId)).thenReturn(Optional.of(expectedUsername));

            // When
            String actualUsername = userService.getUsernameById(userId);

            // Then
            assertThat(actualUsername).isEqualTo(expectedUsername);
            verify(userRepository, times(1)).findUsernameById(userId);
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void getUsernameById_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            UUID userId = UUID.randomUUID();
            when(userRepository.findUsernameById(userId)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> userService.getUsernameById(userId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + userId);

            verify(userRepository, times(1)).findUsernameById(userId);
        }
    }

    @Nested
    @DisplayName("getUserStats Tests")
    class GetUserStatsTests {

        @BeforeEach
        void setUpMocks() {
            // Mock repository count methods
            when(userRepository.count()).thenReturn(100L);
            when(userRepository.countByBannedFalse()).thenReturn(80L);
            when(userRepository.countByBannedTrue()).thenReturn(20L);
            when(userRepository.countByEnabledTrue()).thenReturn(75L);
            when(userRepository.countByRole(Role.ADMIN)).thenReturn(1L); // Added mock for ADMIN role count
        }

        @Test
        @DisplayName("Should return user statistics based on repository counts")
        void getUserStats_shouldReturnCorrectCounts() {
            // When
            UserStatsResponse stats = userService.getUserStats();

            // Then
            assertThat(stats).isNotNull();
            assertThat(stats.getTotalUsers()).isEqualTo(100L);
            assertThat(stats.getActiveUsers()).isEqualTo(80L);
            assertThat(stats.getBannedUsers()).isEqualTo(20L);
            assertThat(stats.getVerifiedUsers()).isEqualTo(75L);
            assertThat(stats.getAdminUsers()).isEqualTo(1L); // Asserting against the mocked value
            assertThat(stats.getTimestamp()).isNotNull();
        }
    }

    // UserService public methods should now be covered by tests.
} 