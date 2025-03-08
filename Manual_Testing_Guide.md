# Manual Testing Guide for User Service

This guide provides comprehensive instructions for manually testing the SavorAI User Service endpoints using curl commands, Postman, and browser testing.

## Prerequisites

- User service running at http://localhost:8081
- MySQL server running with the configured database
- Testing tools: curl, Postman, or Insomnia (optional but recommended)
- A valid email address for registration testing

## Testing Environment Setup

Before starting the tests, ensure your environment is properly set up:

1. Run the setup script:
   ```bash
   # Windows
   .\simple-setup.ps1
   
   # Linux/macOS
   source ./simple-setup.sh
   ```

2. Start the application:
   ```bash
   ./gradlew bootRun
   ```

3. Verify the application is running by accessing:
   ```
   http://localhost:8081/actuator/health
   ```
   
   Expected response: `{"status":"UP"}`

## API Testing

### 1. User Registration

#### Using curl:

```bash
curl -X POST http://localhost:8081/api/v1/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "Password123!"
  }'
```

#### Using Postman:
- Method: POST
- URL: http://localhost:8081/api/v1/user/register
- Headers: Content-Type: application/json
- Body (raw JSON):
  ```json
  {
    "username": "testuser",
    "email": "testuser@example.com",
    "password": "Password123!"
  }
  ```

#### Expected Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "username": "testuser",
  "email": "testuser@example.com"
}
```

#### What to check:
- Verify that you receive a JWT token
- Check your email inbox for verification email
- Save the token for subsequent tests
- Verify HTTP status code is 201 Created

### 2. User Login

#### Using curl:

```bash
curl -X POST http://localhost:8081/api/v1/user/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "Password123!"
  }'
```

#### Expected Response:

```json
{
  "token": "eyJhbGciOiJIUzI1NiJ9...",
  "username": "testuser",
  "email": "testuser@example.com"
}
```

#### What to check:
- Verify that you receive a token
- Save the token for the next tests
- Verify HTTP status code is 200 OK

### 3. Email Verification

#### Using browser:

Open this URL in your browser (replace `YOUR_VERIFICATION_TOKEN` with the actual token from the email):

```
http://localhost:8081/api/v1/user/verify/YOUR_VERIFICATION_TOKEN
```

#### Using curl:

```bash
curl -X GET http://localhost:8081/api/v1/user/verify/YOUR_VERIFICATION_TOKEN
```

#### Expected Response:

You should see a message indicating successful verification:
```
Email verified successfully. You can now login.
```

#### What to check:
- The verification success message
- Try logging in again after verification
- Check the database to confirm the emailVerified field is set to true

### 4. Get Current User Details

#### Using curl:

```bash
curl -X GET http://localhost:8081/api/v1/user/current-user \
  -H "Authorization: Bearer YOUR_JWT_TOKEN"
```

#### Expected Response:

```json
{
  "id": 1,
  "username": "testuser",
  "email": "testuser@example.com",
  "emailVerified": true,
  "createdOn": "2023-01-01T12:00:00",
  "updatedOn": "2023-01-01T12:00:00"
}
```

#### What to check:
- Make sure you can access your user details
- Verify that createdOn and updatedOn timestamps are present
- Verify HTTP status code is 200 OK

### 5. Password Reset Request

#### Using curl:

```bash
curl -X POST http://localhost:8081/api/v1/user/reset-password-request \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com"
  }'
```

#### Expected Response:

```json
{
  "message": "Password reset email sent successfully"
}
```

#### What to check:
- Check your email for the password reset link
- Verify HTTP status code is 200 OK

### 6. Password Reset Confirmation

Using the token from the reset email:

#### Using curl:

```bash
curl -X POST http://localhost:8081/api/v1/user/reset-password \
  -H "Content-Type: application/json" \
  -d '{
    "token": "YOUR_RESET_TOKEN",
    "newPassword": "NewPassword123!"
  }'
```

#### Expected Response:

```json
{
  "message": "Password reset successful"
}
```

#### What to check:
- Try logging in with the new password
- Verify HTTP status code is 200 OK

## Testing Error Cases

### 1. Registration with existing email:

```bash
curl -X POST http://localhost:8081/api/v1/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "anotheruser",
    "email": "testuser@example.com",
    "password": "Password123!"
  }'
```

Expected: 
- Error message about email already in use
- HTTP status code 400 Bad Request

### 2. Registration with invalid password:

```bash
curl -X POST http://localhost:8081/api/v1/user/register \
  -H "Content-Type: application/json" \
  -d '{
    "username": "weakuser",
    "email": "weak@example.com",
    "password": "weak"
  }'
```

Expected:
- Validation error message about password requirements
- HTTP status code 400 Bad Request

### 3. Login with incorrect password:

```bash
curl -X POST http://localhost:8081/api/v1/user/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "testuser@example.com",
    "password": "wrongpassword"
  }'
```

Expected:
- Authentication error
- HTTP status code 401 Unauthorized

### 4. Invalid verification token:

```bash
curl -X GET http://localhost:8081/api/v1/user/verify/INVALID_TOKEN
```

Expected:
- Error message about invalid verification token
- HTTP status code 400 Bad Request

### 5. Accessing protected endpoint without token:

```bash
curl -X GET http://localhost:8081/api/v1/user/current-user
```

Expected:
- Authentication error
- HTTP status code 401 Unauthorized

### 6. Accessing protected endpoint with expired token:

Use an expired or invalid token:

```bash
curl -X GET http://localhost:8081/api/v1/user/current-user \
  -H "Authorization: Bearer INVALID_TOKEN"
```

Expected:
- Authentication error
- HTTP status code 401 Unauthorized

## Performance Testing

For basic performance testing, you can use Apache Bench:

```bash
# Test the health endpoint with 100 requests, 10 concurrent
ab -n 100 -c 10 http://localhost:8081/actuator/health

# Test the login endpoint with 50 requests, 5 concurrent
ab -n 50 -c 5 -p login-data.json -T application/json http://localhost:8081/api/v1/user/login
```

Create login-data.json with:
```json
{
  "email": "testuser@example.com",
  "password": "Password123!"
}
```

## Troubleshooting

### Common Issues

1. **JWT Token Issues**:
   - Check if the token is properly formatted
   - Verify the token hasn't expired
   - Ensure you're using the correct secret key

2. **Email Verification Issues**:
   - Check spam folder for verification emails
   - Verify the email service configuration
   - Check application logs for email sending errors

3. **Database Connection Issues**:
   - Verify MySQL is running
   - Check database credentials
   - Ensure the database exists and has the correct schema

### Debugging Tips

1. Enable debug logging by adding this to application.yml:
   ```yaml
   logging:
     level:
       dev.idachev.userservice: DEBUG
   ```

2. Use JWT.io to decode and inspect your JWT tokens

3. Check application logs for detailed error messages

## Additional Resources

- [Postman Collection](https://www.postman.com/collections/your-collection-id) - Import this collection for easier testing
- [JWT.io](https://jwt.io/) - Decode and verify JWT tokens
- [Spring Security Documentation](https://docs.spring.io/spring-security/reference/index.html) 