package dev.idachev.userservice.service;

import dev.idachev.userservice.exception.InvalidRequestException;
import dev.idachev.userservice.exception.ResourceNotFoundException;
import dev.idachev.userservice.mapper.DtoMapper;
import dev.idachev.userservice.model.User;
import dev.idachev.userservice.repository.UserRepository;
import dev.idachev.userservice.web.dto.PasswordChangeRequest;
import dev.idachev.userservice.web.dto.UserResponse;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
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

import java.util.Optional;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
@DisplayName("ProfileService Tests")
@MockitoSettings(strictness = Strictness.LENIENT)
class ProfileServiceUTest {

    @Mock
    private UserRepository userRepository;
    @Mock
    private PasswordEncoder passwordEncoder;
    @Mock
    private CacheManager cacheManager;
    @Mock
    private Cache usersCache; // Mock for cache eviction verification
    @Mock
    private Cache usernamesCache; // Mock for cache eviction verification

    @InjectMocks
    private ProfileService profileService;

    private MockedStatic<DtoMapper> dtoMapperMockedStatic;

    private final String TEST_USERNAME = "profileUser";
    private final String TEST_EMAIL = "profile@test.com";
    private final UUID TEST_USER_ID = UUID.randomUUID();
    private final String CURRENT_PASSWORD_PLAIN = "currentPass123";
    private final String CURRENT_PASSWORD_ENCODED = "encodedCurrentPass123";
    private User testUser;

    @BeforeEach
    void setUp() {
        dtoMapperMockedStatic = Mockito.mockStatic(DtoMapper.class);
        testUser = User.builder()
                .id(TEST_USER_ID)
                .username(TEST_USERNAME)
                .email(TEST_EMAIL)
                .password(CURRENT_PASSWORD_ENCODED)
                .build();

        // Mock cache manager to return mock caches with lenient setting
        lenient().when(cacheManager.getCache("users")).thenReturn(usersCache);
        lenient().when(cacheManager.getCache("usernames")).thenReturn(usernamesCache);
    }

    @AfterEach
    void tearDown() {
        dtoMapperMockedStatic.close();
    }

    @Nested
    @DisplayName("getUserInfoByUsername Tests")
    class GetUserInfoTests {

        @Test
        @DisplayName("Should return UserResponse when user found")
        void getUserInfoByUsername_whenUserFound_shouldReturnUserResponse() {
            // Given
            UserResponse expectedResponse = UserResponse.builder().id(TEST_USER_ID).username(TEST_USERNAME).build();
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            dtoMapperMockedStatic.when(() -> DtoMapper.mapToUserResponse(testUser)).thenReturn(expectedResponse);

            // When
            UserResponse actualResponse = profileService.getUserInfoByUsername(TEST_USERNAME);

            // Then
            assertThat(actualResponse).isEqualTo(expectedResponse);
            verify(userRepository).findByUsername(TEST_USERNAME);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(testUser));
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user not found")
        void getUserInfoByUsername_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> profileService.getUserInfoByUsername(TEST_USERNAME))
                .isInstanceOf(ResourceNotFoundException.class);
            verify(userRepository).findByUsername(TEST_USERNAME);
            dtoMapperMockedStatic.verify(() -> DtoMapper.mapToUserResponse(any()), never());
        }

        @Test
        @DisplayName("Should throw InvalidRequestException for blank username")
        void getUserInfoByUsername_withBlankUsername_shouldThrowInvalidRequestException() {
             assertThatThrownBy(() -> profileService.getUserInfoByUsername(null))
                .isInstanceOf(InvalidRequestException.class);
             assertThatThrownBy(() -> profileService.getUserInfoByUsername("   "))
                .isInstanceOf(InvalidRequestException.class);
            verifyNoInteractions(userRepository);
        }
    }

    @Nested
    @DisplayName("deleteAccount Tests")
    class DeleteAccountTests {

        @Test
        @DisplayName("Should delete user and evict caches when user found")
        void deleteAccount_whenUserFound_shouldDeleteAndEvictCaches() {
            // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            doNothing().when(userRepository).delete(testUser);
            doNothing().when(usersCache).evict(any()); // Mock cache interactions
            doNothing().when(usernamesCache).evict(any());

            // When
            profileService.deleteAccount(TEST_USERNAME);

            // Then
            verify(userRepository).findByUsername(TEST_USERNAME);
            verify(userRepository).delete(testUser);
            // Verify cache evictions
            verify(usersCache).evict(TEST_USER_ID);
            verify(usersCache).evict("'username_'" + TEST_USERNAME);
            verify(usersCache).evict("'email_'" + TEST_EMAIL);
            verify(usersCache).evict("'allUsers'");
            verify(usernamesCache).evict(TEST_USER_ID);
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user not found")
        void deleteAccount_whenUserNotFound_shouldThrowResourceNotFoundException() {
             // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.empty());

            // When & Then
            assertThatThrownBy(() -> profileService.deleteAccount(TEST_USERNAME))
                .isInstanceOf(ResourceNotFoundException.class);
            verify(userRepository).findByUsername(TEST_USERNAME);
            verify(userRepository, never()).delete(any());
             verifyNoInteractions(usersCache, usernamesCache);
        }
    }

    @Nested
    @DisplayName("changePassword Tests")
    class ChangePasswordTests {

        private PasswordChangeRequest validRequest;
        private final String NEW_PASSWORD_PLAIN = "newPass456";
        private final String NEW_PASSWORD_ENCODED = "encodedNewPass456";

        @BeforeEach
        void setupRequest() {
             validRequest = PasswordChangeRequest.builder()
                            .currentPassword(CURRENT_PASSWORD_PLAIN)
                            .newPassword(NEW_PASSWORD_PLAIN)
                            .confirmPassword(NEW_PASSWORD_PLAIN)
                            .build();
        }

        @Test
        @DisplayName("Should change password and evict caches when request is valid")
        void changePassword_withValidRequest_shouldChangePasswordAndEvictCaches() {
            // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED)).thenReturn(true);
            when(passwordEncoder.encode(NEW_PASSWORD_PLAIN)).thenReturn(NEW_PASSWORD_ENCODED);
            when(userRepository.save(any(User.class))).thenAnswer(inv -> inv.getArgument(0));
            doNothing().when(usersCache).evict(any());
            doNothing().when(usernamesCache).evict(any());

            // When
            profileService.changePassword(TEST_USERNAME, validRequest);

            // Then
            verify(userRepository).findByUsername(TEST_USERNAME);
            verify(passwordEncoder).matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED);
            verify(passwordEncoder).encode(NEW_PASSWORD_PLAIN);

            ArgumentCaptor<User> userCaptor = ArgumentCaptor.forClass(User.class);
            verify(userRepository).save(userCaptor.capture());
            assertThat(userCaptor.getValue().getPassword()).isEqualTo(NEW_PASSWORD_ENCODED);

             // Verify cache evictions
            verify(usersCache).evict(TEST_USER_ID);
            verify(usersCache).evict("'username_'" + TEST_USERNAME);
            verify(usersCache).evict("'email_'" + TEST_EMAIL);
            verify(usersCache).evict("'allUsers'");
            verify(usernamesCache).evict(TEST_USER_ID);
        }

        @Test
        @DisplayName("Should throw ResourceNotFoundException when user not found")
        void changePassword_whenUserNotFound_shouldThrowResourceNotFoundException() {
            // Given
             when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.empty());

             // When & Then
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, validRequest))
                .isInstanceOf(ResourceNotFoundException.class);
             verify(userRepository).findByUsername(TEST_USERNAME);
             verifyNoInteractions(passwordEncoder);
             verify(userRepository, never()).save(any());
             verifyNoInteractions(usersCache, usernamesCache);
        }

         @Test
        @DisplayName("Should throw InvalidRequestException when current password incorrect")
        void changePassword_whenCurrentPasswordIncorrect_shouldThrowInvalidRequestException() {
            // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED)).thenReturn(false); // Incorrect match

             // When & Then
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, validRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessageContaining("Current password is incorrect");

            verify(userRepository).findByUsername(TEST_USERNAME);
            verify(passwordEncoder).matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED);
            verify(passwordEncoder, never()).encode(any());
            verify(userRepository, never()).save(any());
        }

        @Test
        @DisplayName("Should throw InvalidRequestException when new passwords do not match")
        void changePassword_whenNewPasswordsMismatch_shouldThrowInvalidRequestException() {
            // Given
            PasswordChangeRequest mismatchRequest = PasswordChangeRequest.builder()
                            .currentPassword(CURRENT_PASSWORD_PLAIN)
                            .newPassword(NEW_PASSWORD_PLAIN)
                            .confirmPassword("doesNotMatch")
                            .build();
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            when(passwordEncoder.matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED)).thenReturn(true);

             // When & Then
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, mismatchRequest))
                .isInstanceOf(InvalidRequestException.class)
                .hasMessageContaining("do not match");

            verify(userRepository).findByUsername(TEST_USERNAME);
            verify(passwordEncoder).matches(CURRENT_PASSWORD_PLAIN, CURRENT_PASSWORD_ENCODED);
            verify(passwordEncoder, never()).encode(any());
            verify(userRepository, never()).save(any());
        }

         @Test
        @DisplayName("Should throw NullPointerException when required fields in request are null")
        void changePassword_withNullFieldsInRequest_shouldThrowNPE() {
            // Given
            when(userRepository.findByUsername(TEST_USERNAME)).thenReturn(Optional.of(testUser));
            PasswordChangeRequest nullCurrent = PasswordChangeRequest.builder().currentPassword(null).newPassword("n").confirmPassword("n").build();
            PasswordChangeRequest nullNew = PasswordChangeRequest.builder().currentPassword("c").newPassword(null).confirmPassword("n").build();
            PasswordChangeRequest nullConfirm = PasswordChangeRequest.builder().currentPassword("c").newPassword("n").confirmPassword(null).build();

            // When & Then (Checking for NullPointerException due to Objects.requireNonNull)
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, nullCurrent))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Current password cannot be null");
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, nullNew))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("New password cannot be null");
            // Check confirm password *after* current password check passes
            when(passwordEncoder.matches(any(), any())).thenReturn(true);
             assertThatThrownBy(() -> profileService.changePassword(TEST_USERNAME, nullConfirm))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("Confirm password cannot be null");
        }
    }
} 