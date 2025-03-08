# SavorAI User Service Setup

This document provides a comprehensive guide to set up and run the SavorAI User Service.

## Prerequisites

- Java 17 or higher
- MySQL database (5.7+)
- Windows, Linux, or macOS
- Gradle (or use the included wrapper)

## Quick Setup

### 1. Database Setup

Ensure your MySQL database is running. The application will create a database named `savorAI_user` if it doesn't exist.

Default credentials (configured in application.yml):
- Username: `root`
- Password: `root`

For production, create a dedicated database user with limited permissions:

```sql
CREATE USER 'savorai_app'@'localhost' IDENTIFIED BY 'strong_password';
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, ALTER, INDEX, DROP ON savorAI_user.* TO 'savorai_app'@'localhost';
FLUSH PRIVILEGES;
```

### 2. Environment Variables

You need to set environment variables for the user service to work properly.

**Option 1: Using simplified setup scripts (recommended for development)**

- **Windows**: Run the PowerShell script
  ```
  .\simple-setup.ps1
  ```

- **Linux/macOS**: Run the bash script
  ```
  source ./simple-setup.sh
  ```

**Option 2: Set variables manually**

Set these environment variables in your system:
- `DB_USERNAME` - Database username (default: root)
- `DB_PASSWORD` - Database password (default: root)
- `JWT_SECRET` - Secret key for JWT token generation
- `MAIL_USERNAME` - Email for sending verification emails
- `MAIL_PASSWORD` - App password for the email account

**Option 3: Production deployment**

For production environments:
1. Generate a secure JWT secret using the provided utility
2. Store environment variables securely in your deployment platform
3. Consider using a secrets management service like HashiCorp Vault or AWS Secrets Manager

### 3. Generate a Secure JWT Secret

For production, you should generate a secure JWT secret:

1. Compile the utility:
   ```
   javac GenerateJwtSecret.java
   ```

2. Run it:
   ```
   java GenerateJwtSecret
   ```

3. Copy the generated key and use it in your environment variables.

### 4. Run the Application

After setting up the environment variables, run:

```
./gradlew bootRun
```

The application will be available at: http://localhost:8081

## Configuration Options

### Application Properties

The main configuration file is `src/main/resources/application.yml`. Key settings include:

- `server.port`: The port the application runs on (default: 8081)
- `spring.datasource`: Database connection settings
- `spring.mail`: Email service configuration
- `jwt`: JWT token settings
- `security`: Security-related configurations

### Email Configuration

The application uses Gmail SMTP for sending verification emails. For production:

1. Consider using a transactional email service like SendGrid or Mailgun
2. Update the mail configuration in application.yml accordingly

## Security Best Practices

1. **JWT Secret**: Always use a strong, randomly generated secret key
2. **Database**: Use a dedicated database user with limited permissions
3. **Credentials**: Never commit credentials to version control
4. **HTTPS**: Configure SSL/TLS in production
5. **Regular Updates**: Keep dependencies updated using:
   ```
   ./gradlew dependencyUpdates
   ```
6. **Vulnerability Scanning**: Run security checks with:
   ```
   ./gradlew dependencyCheckAnalyze
   ```

## Troubleshooting

### Common Issues

1. **Database Connection Errors**:
   - Verify MySQL is running
   - Check database credentials
   - Ensure the database user has proper permissions

2. **Email Sending Failures**:
   - Verify SMTP settings
   - For Gmail, ensure "Less secure app access" is enabled or use an app password

3. **JWT Token Issues**:
   - Ensure JWT_SECRET is properly set
   - Check token expiration settings

### Logs

Application logs are available in the `logs` directory and in the console output.

## Additional Resources

- [Spring Boot Documentation](https://docs.spring.io/spring-boot/docs/current/reference/html/)
- [JWT Authentication Guide](https://jwt.io/introduction)
- [MySQL Documentation](https://dev.mysql.com/doc/) 