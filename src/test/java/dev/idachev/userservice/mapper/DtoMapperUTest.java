package dev.idachev.userservice.mapper;

import dev.idachev.userservice.model.Role;
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
    private UUID testId;

    @BeforeEach
    void setUp() {
        testToken = "test.jwt.token";
        testMessage = "Test message";
        testStatus = 200;
        testDate = LocalDateTime.now();
        testId = UUID.randomUUID();

        testUser = User.builder()
                .id(testId)
                .username("testUser")
                .email("test@example.com")
                .password("encoded_password")
                .enabled(true)
                .verificationToken(null)
                .role(Role.USER)
                .createdOn(LocalDateTime.now().minusDays(1))
                .updatedOn(LocalDateTime.now().minusHours(1))
                .lastLogin(testDate)
                .build();
    }

    @Test
    void whenMapToUserResponse_thenReturnUserResponseDTO() {
        UserResponse response = DtoMapper.mapToUserResponse(testUser);

        assertNotNull(response);
        assertEquals(testId, response.getId());
        assertEquals(testUser.getUsername(), response.getUsername());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertFalse(response.isVerificationPending());
        assertEquals(Role.USER, response.getRole());
        assertEquals(testUser.getCreatedOn(), response.getCreatedOn());
        assertEquals(testUser.getLastLogin(), response.getLastLogin());
    }

    @Test
    void givenNullUser_whenMapToUserResponse_thenThrowIllegalArgumentException() {
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> DtoMapper.mapToUserResponse(null)
        );

        assertEquals("Cannot map null user to UserResponse", exception.getMessage());
    }

    @Test
    void whenMapToAuthResponseWithToken_thenReturnAuthResponseWithToken() {
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, testToken);

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
        IllegalArgumentException exception = assertThrows(
                IllegalArgumentException.class,
                () -> DtoMapper.mapToAuthResponse(null, testToken)
        );

        assertEquals("Cannot map null user to AuthResponse", exception.getMessage());
    }

    @Test
    void givenNullToken_whenMapToAuthResponseWithToken_thenUseEmptyString() {
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, null);

        assertNotNull(response);
        assertEquals("", response.getToken());
    }

    @Test
    void whenMapToAuthResponseWithUserAndSuccessMessage_thenReturnCorrectDTO() {
        boolean success = true;
        
        AuthResponse response = DtoMapper.mapToAuthResponse(testUser, success, testMessage);

        assertNotNull(response);
        assertEquals(testUser.getUsername(), response.getUsername());
        assertEquals(testUser.getEmail(), response.getEmail());
        assertTrue(response.isVerified());
        assertFalse(response.isVerificationPending());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void givenNullUser_whenMapToAuthResponseWithStatusMessage_thenReturnSimpleResponse() {
        boolean success = false;

        AuthResponse response = DtoMapper.mapToAuthResponse(null, success, testMessage);

        assertNotNull(response);
        assertNull(response.getUsername());
        assertNull(response.getEmail());
        assertFalse(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void whenMapToAuthResponseWithSuccessMessage_thenReturnSimpleResponseDTO() {
        boolean success = true;

        AuthResponse response = DtoMapper.mapToAuthResponse(success, testMessage);

        assertNotNull(response);
        assertNull(response.getUsername());
        assertNull(response.getEmail());
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
    }

    @Test
    void givenNullMessage_whenMapToAuthResponse_thenUseEmptyString() {
        AuthResponse response = DtoMapper.mapToAuthResponse(true, null);

        assertNotNull(response);
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToVerification_thenReturnCorrectDTO() {
        boolean success = true;

        VerificationResponse response = DtoMapper.mapToVerificationResponse(testUser, success, testMessage);

        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
        assertNotNull(response.getData());

        UserResponse userData = (UserResponse) response.getData();
        assertEquals(testUser.getUsername(), userData.getUsername());
        assertEquals(testUser.getEmail(), userData.getEmail());
    }

    @Test
    void givenNullUser_whenMapToVerificationResponse_thenReturnResponseWithNullData() {
        boolean success = false;

        VerificationResponse response = DtoMapper.mapToVerificationResponse(null, success, testMessage);

        assertNotNull(response);
        assertFalse(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
        assertNull(response.getData());
    }

    @Test
    void givenNullMessage_whenMapToVerificationResponse_thenUseEmptyString() {
        VerificationResponse response = DtoMapper.mapToVerificationResponse(null, false, null);

        assertNotNull(response);
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToGenericResponse_thenReturnCorrectDTO() {
        GenericResponse response = DtoMapper.mapToGenericResponse(testStatus, testMessage);

        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void givenNullMessage_whenMapToGenericResponse_thenUseEmptyString() {
        GenericResponse response = DtoMapper.mapToGenericResponse(testStatus, null);

        assertNotNull(response);
        assertEquals(testStatus, response.getStatus());
        assertEquals("", response.getMessage());
    }

    @Test
    void whenMapToEmailVerificationResponse_thenReturnCorrectDTO() {
        boolean success = true;

        EmailVerificationResponse response = DtoMapper.mapToEmailVerificationResponse(success, testMessage);

        assertNotNull(response);
        assertTrue(response.isSuccess());
        assertEquals(testMessage, response.getMessage());
        assertNotNull(response.getTimestamp());
    }

    @Test
    void givenNullMessage_whenMapToEmailVerificationResponse_thenUseEmptyString() {
        EmailVerificationResponse response = DtoMapper.mapToEmailVerificationResponse(false, null);

        assertNotNull(response);
        assertEquals("", response.getMessage());
    }
}