package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.User;
import dev.idachev.userservice.web.dto.*;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.LocalDateTime;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;

@ExtendWith(MockitoExtension.class)
public class DtoMapperUTest {

    private User testUser;
    private String testToken;
    private String testMessage;
    private int testStatus;
    private LocalDateTime testDate;

    @BeforeEach
    void setUp() {
        testDate = LocalDateTime.now();
        testToken = UUID.randomUUID().toString();
        testMessage = "Test message";
        testStatus = 200;

        testUser = User.builder()
                .id(UUID.randomUUID())
                .username("testUser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(true)
                .verificationToken(null) // No verification pending
                .createdOn(LocalDateTime.now().minusDays(1))
                .updatedOn(LocalDateTime.now().minusHours(1))
                .lastLogin(testDate)
                .build();
    }

    @Test
    void whenMapToUserResponse_thenReturnUserResponseDTO() {

        // When
        UserResponse response = DtoMapper.mapToUserResponse(testUser);

        // Then
        assertNotNull(response);
        assertEquals(testUser.getUsername(), response.getUsername());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertFalse(response.isVerificationPending());
        assertEquals(testUser.getLastLogin(), response.getLastLogin());
    }

    @Test
    void givenNullUser_whenMapToUserResponse_thenThrowIllegalArgumentException() {

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> DtoMapper.mapToUserResponse(null)
        );

        assertEquals("Cannot map null user to UserResponse", exception.getMessage());
    }

    @Test
    void whenMapToAuthResponseWithToken_thenReturnAuthResponseWithToken() {

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, testToken);

        //Then
        assertNotNull(response);
        assertEquals(testUser.getUsername(), response.getUsername());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertFalse(response.isVerificationPending());
        assertEquals(testToken, response.getToken());
        assertTrue(response.isSuccess());
        assertEquals("", response.getMessage());
    }

    @Test
    void givenNullUser_whenMapToAuthResponseWithToken_thenThrowIllegalArgumentException() {

        // When & Then
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> DtoMapper.mapToAuthResponse(null, testToken)
        );

        assertEquals("Cannot map null user to AuthResponse", exception.getMessage());
    }

    @Test
    void givenNullToken_whenMapToAuthResponseWithToken_thenUseEmptyString() {

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, null);

        // Then
        assertNotNull(response);
        assertEquals("", response.getToken());
    }

    @Test
    void whenMapToAuthResponseWithUserAndSuccessMessage_thenReturnCorrectDTO() {

        // Given
        boolean success = true;

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, success, testMessage);

        // Then
        assertNotNull(response);
        assertEquals(testUser.getUsername(), response.getUsername());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertFalse(response.isVerificationPending());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void givenNullUser_whenMapToAuthResponseWithStatusMessage_thenReturnSimpleResponse() {

        // Given
        boolean success = false;

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(null, success, testMessage);

        // Then
        assertNotNull(response);
        assertNull(response.getUsername());
        assertNull(response.getEmail());
        assertFalse(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void whenMapToAuthResponseWithSuccessMessage_thenReturnSimpleResponseDTO() {

        // Given
        boolean success = true;

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(success, testMessage);

        // Then
        assertNotNull(response);
        assertNull(response.getUsername());
        assertNull(response.getEmail());
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void givenNullMessage_whenMapToAuthResponse_thenUseEmptyString() {

        // When
        AuthResponse response = DtoMapper.mapToAuthResponse(true, null);

        // Then
        assertNotNull(response);
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToVerification_thenReturnCorrectDTO() {

        // Given
        boolean success = true;

        // When
        VerificationResponse response = DtoMapper.mapToVerificationResponse(testUser, success, testMessage);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
        assertNotNull(response.getData());

        // Verify the nested UserResponse in data
        UserResponse userData = (UserResponse) response.getData();
        assertEquals(testUser.getUsername(), userData.getUsername());
        assertEquals(testUser.getEmail(), userData.getEmail());
    }

    @Test
    void givenNullUser_whenMapToVerificationResponse_thenReturnResponseWithNullData() {

        // Given
        boolean success = false;

        // When
        VerificationResponse response = DtoMapper.mapToVerificationResponse(null, success, testMessage);

        // Then
        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
        assertNull(response.getData());
    }


    @Test
    void givenNullMessage_whenMapToVerificationResponse_thenUseEmptyString() {

        // When
        VerificationResponse response = DtoMapper.mapToVerificationResponse(null, false, null);

        // Then
        assertNotNull(response);
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToErrorResponse_thenReturnCorrectDTO() {

        // When
        ErrorResponse response = DtoMapper.mapToErrorResponse(testStatus, testMessage);

        // Then
        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void givenNullMessage_whenMapToErrorResponse_thenUseDefaultErrorMessage() {

        // When
        ErrorResponse response = DtoMapper.mapToErrorResponse(testStatus, null);

        // Then
        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals("An error occurred", response.getMessage());
    }

    @Test
    void whenMapToGenericResponse_thenReturnCorrectDTO() {

        // When
        GenericResponse response = DtoMapper.mapToGenericResponse(testStatus, testMessage);

        // Then
        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void givenNullMessage_whenMapToGenericResponse_thenUseEmptyString() {

        // When
        GenericResponse response = DtoMapper.mapToGenericResponse(testStatus, null);

        // Then
        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToEmailVerificationResponse_thenReturnCorrectDTO() {

        // Given
        boolean success = true;

        // When
        EmailVerificationResponse response = DtoMapper.mapToEmailVerificationResponse(success, testMessage);

        // Then
        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void givenNullMessage_whenMapToEmailVerificationResponse_thenUseEmptyString() {

        // When
        EmailVerificationResponse response = DtoMapper.mapToEmailVerificationResponse(false, null);

        // Then
        assertNotNull(response);
        assertEquals("", response.getMessage());
    }
}