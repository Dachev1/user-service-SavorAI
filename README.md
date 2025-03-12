# SavorAI User Service

User authentication and account management service for the SavorAI platform.

## Features

- User registration and authentication
- Email verification
- JWT-based authentication
- Secure password handling
- Account management

## Technology Stack

- Java 17
- Spring Boot 3.2.x
- Spring Security
- Spring Data JPA
- MySQL Database
- Thymeleaf (for email templates)

## Setup and Configuration

### Prerequisites

- JDK 17 or later
- MySQL 8.0 or later
- Gradle 8.x

### Environment Variables

This application uses environment variables for sensitive configuration. Before running, make sure to set the following environment variables:

```
# Database Configuration
DB_USERNAME=your_database_username
DB_PASSWORD=your_database_password

# Email Service Configuration
MAIL_USERNAME=your_email_username
MAIL_PASSWORD=your_email_password

# JWT Configuration
JWT_SECRET=your_jwt_secret_key
```

You can either set these in your environment or create a `.env` file in the root directory (this file is gitignored and should never be committed to version control).

### Running the Application

Using Gradle Wrapper:

```bash
# For Windows
./gradlew.bat bootRun

# For Unix/Linux/MacOS
./gradlew bootRun
```

Note for Windows PowerShell users: Use semicolons instead of && for command chaining:
```powershell
cd user-service; ./gradlew.bat bootRun
```

The application will start on port 8081 by default (configurable in application.yml).

## API Endpoints

- `POST /api/v1/user/register` - Register a new user
- `POST /api/v1/user/login` - Authenticate a user
- `GET /api/v1/user/verify-email/{token}` - Verify user email
- More endpoints documented in the code

## Development Notes

- The main application configuration is in `src/main/resources/application.yml`
- Environment-specific configurations should use profile-specific YML files (e.g. `application-dev.yml`)
- Email templates are located in `src/main/resources/templates/email/` 