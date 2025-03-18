# SavorAI User Service

![Java](https://img.shields.io/badge/Java-17-orange)
![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.2.x-green)
![MySQL](https://img.shields.io/badge/MySQL-8.0-blue)
![License](https://img.shields.io/badge/License-MIT-yellow)

User authentication and account management microservice for the SavorAI platform. This service handles all user-related operations including registration, authentication, profile management, and security.

## 📋 Features

- **User Management**
  - Registration with email verification
  - Login/logout functionality
  - Password reset workflows
  - Account activation/deactivation
  
- **Security**
  - JWT-based authentication
  - Role-based access control
  - Secure password hashing
  - Protection against common attacks
  
- **Profile Management**
  - User profile creation and editing
  - Preference management
  - Activity history

## 🛠️ Technology Stack

- **Backend**
  - Java 17
  - Spring Boot 3.2.x
  - Spring Security
  - Spring Data JPA
  - Hibernate
  
- **Database**
  - MySQL 8.0+
  
- **Email**
  - Spring Mail
  - Thymeleaf (for email templates)
  
- **Documentation**
  - OpenAPI/Swagger
  
- **Testing**
  - JUnit 5
  - Mockito

## 🚀 Getting Started

### Prerequisites

- JDK 17 or later
- MySQL 8.0 or later
- Gradle 8.x

### Configuration

This application uses environment variables for sensitive configuration. Before running, set up the following:

#### Option 1: Environment Variables

Set these environment variables in your system:

```bash
# Database Configuration
export DB_USERNAME=your_database_username
export DB_PASSWORD=your_database_password

# Email Service Configuration
export MAIL_USERNAME=your_email_username
export MAIL_PASSWORD=your_email_password

# JWT Configuration
export JWT_SECRET=your_jwt_secret_key
```

#### Option 2: Properties File

Create a `.env.properties` file in `src/main/resources/` with the following content:

```properties
DB_USERNAME=your_database_username
DB_PASSWORD=your_database_password
MAIL_USERNAME=your_email_username
MAIL_PASSWORD=your_email_password
JWT_SECRET=your_jwt_secret_key
```

> ⚠️ **Important**: If using a Gmail account for sending emails, you must use an App Password instead of your regular password. Spaces in the App Password should be removed.

### Building the Application

```bash
# Clone the repository
git clone https://github.com/yourusername/savorai-user-service.git
cd savorai-user-service

# Build the project
./gradlew build
```

### Running the Application

```bash
# For Windows
./gradlew.bat bootRun

# For Unix/Linux/MacOS
./gradlew bootRun
```

The application will start on port 8081 by default (configurable in `application.yml`).

## 📝 API Documentation

Once the application is running, access the Swagger UI at:
```
http://localhost:8081/swagger-ui.html
```

### Core Endpoints

| Method | Endpoint | Description | Auth Required |
|--------|----------|-------------|--------------|
| POST | `/api/v1/auth/register` | Register a new user | No |
| POST | `/api/v1/auth/login` | Authenticate a user | No |
| GET | `/api/v1/auth/verify-email/{token}` | Verify email address | No |
| POST | `/api/v1/auth/password/reset-request` | Request password reset | No |
| POST | `/api/v1/auth/password/reset` | Reset password with token | No |
| GET | `/api/v1/user/me` | Get current user profile | Yes |
| PUT | `/api/v1/user/me` | Update user profile | Yes |

## 🔧 Development

### Project Structure

```
src/
├── main/
│   ├── java/
│   │   └── dev.idachev.userservice/
│   │       ├── config/        # Application configuration
│   │       ├── domain/        # Domain models
│   │       ├── repository/    # Data access layer
│   │       ├── security/      # Security configurations
│   │       ├── service/       # Business logic
│   │       ├── web/           # Controllers and DTOs
│   │       └── UserServiceApplication.java
│   └── resources/
│       ├── templates/         # Email templates
│       └── application.yml    # Application configuration
└── test/                      # Unit and integration tests
```

### Running Tests

```bash
./gradlew test
```

## ⚠️ Troubleshooting

### Common Issues

#### Email Authentication Errors

If you encounter `jakarta.mail.AuthenticationFailedException`:

1. Ensure you're using an App Password if using Gmail (with 2FA enabled)
2. Remove any spaces from the App Password
3. Verify the email credentials are correctly set in your configuration

#### Database Connection Issues

1. Ensure MySQL is running and accessible
2. Verify the database exists or the user has permission to create it
3. Check database credentials in your configuration

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👥 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request 