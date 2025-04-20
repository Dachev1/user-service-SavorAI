package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.web.mapper.DtoMapper;
import dev.idachev.userservice.model.Role;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.UserResponse;
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
import org.springframework.cache.CacheManager;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("UserService Tests")
class UserServiceTest {

    @Mock
    private UserRepository userRepository;

    @Mock
    private CacheManager cacheManager; // Mocked but not used in this specific test yet

    @Mock
    private PasswordEncoder passwordEncoder; // Mocked but not used in this specific test yet

    @Mock
    private EmailService emailService; // Mocked but not used in this specific test yet

    @Mock
    private TokenService tokenService; // Mocked but not used in this specific test yet

    @Mock
    private VerificationService verificationService; // Mocked but not used in this specific test yet

    @InjectMocks
    private UserService userService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;

    @BeforeEach
    void setUp() {
        // Mock the static DtoMapper.mapToUserResponse method
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
    }

    @AfterEach
    void tearDown() {
        // Close the static mock after each test
        dtoMapperMockedStatic.close();
    }

    @Nested
    @DisplayName("getUserById Tests")
    class GetUserByIdTests {

        @Test
        @DisplayName("Should return user when user exists")
        void getUserById_whenUserExists_shouldReturnUserResponse() {
            // Given
            UUID userId = UUID.randomUUID();
            LocalDateTime now = LocalDateTime.now();
            User mockUser = User.builder()
                    .id(userId)
                    .username("testuser")
                    .password("password123") // Password needed for builder, but not used in this specific logic
                    .email("test@example.com")
                    .role(Role.USER)
                    .enabled(true)
                    .banned(false)
                    .createdOn(now)
                    .updatedOn(now)
                    .verificationToken(null)
                    .build();

            // Assume UserResponse builder exists and map relevant fields
            UserResponse expectedResponse = UserResponse.builder()
                    .id(userId)
                    .username("testuser")
                    .email("test@example.com")
                    .role(Role.USER.name()) // Assuming role in UserResponse is String
                    .enabled(true)
                    .banned(false)
                    .createdOn(now)
                    // Add other fields from UserResponse as null/default if needed
                    .firstName(null)
                    .lastName(null)
                    .bio(null)
                    .verificationPending(false) // Assuming calculated or default
                    .lastLogin(null)
                    .build();

            when(userRepository.findById(userId)).thenReturn(Optional.of(mockUser));
            // Ensure the static mock handles the User object correctly
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(mockUser)).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = userService.getUserById(userId);

            // Then
            assertThat(actualResponse).isNotNull();
            // Use getters instead of record-style accessors
            assertThat(actualResponse.getId()).isEqualTo(expectedResponse.getId());
            assertThat(actualResponse.getUsername()).isEqualTo(expectedResponse.getUsername());
            assertThat(actualResponse.getEmail()).isEqualTo(expectedResponse.getEmail());
            assertThat(actualResponse.getRole()).isEqualTo(expectedResponse.getRole()); // Compare String roles
            assertThat(actualResponse.isEnabled()).isEqualTo(expectedResponse.isEnabled());
            assertThat(actualResponse.isBanned()).isEqualTo(expectedResponse.isBanned());
            assertThat(actualResponse.getCreatedOn()).isEqualTo(expectedResponse.getCreatedOn());
            // Add assertions for other fields if necessary

            verify(userRepository, times(1)).findById(userId);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(mockUser), times(1));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user does not exist")
        void getUserById_whenUserDoesNotExist_shouldThrowResourceNotFoundException() {
            // Given
            UUID userId = UUID.randomUUID();
            when(userRepository.findById(userId)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> userService.getUserById(userId))
                    .isInstanceOf(ResourceNotFoundException.class)
                    .hasMessageContaining("User not found with id: " + userId);

            verify(userRepository, times(1)).findById(userId);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any(User.class)), never());
        }
    }

    // --- Add more test classes (Nested) for other methods ---
    // e.g., RegisterUserTests, GetAllUsersTests, UpdateUserRoleTests, etc.
} 