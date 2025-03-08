import java.security.SecureRandom;
import java.util.Base64;

/**
 * Utility to generate a secure JWT secret key
 * Run with: java GenerateJwtSecret
 */
public class GenerateJwtSecret {
    
    public static void main(String[] args) {
        // Generate a secure random byte array (32 bytes = 256 bits)
        SecureRandom secureRandom = new SecureRandom();
        byte[] secret = new byte[32];
        secureRandom.nextBytes(secret);
        
        // Encode it as Base64 for use in configuration
        String encodedSecret = Base64.getEncoder().encodeToString(secret);
        
        System.out.println("\n========= GENERATED JWT SECRET =========");
        System.out.println(encodedSecret);
        System.out.println("=======================================");
        System.out.println("\nUse this secret in your environment variables setup:");
        System.out.println("- For PowerShell script: $env:JWT_SECRET = \"" + encodedSecret + "\"");
        System.out.println("- For Bash script: export JWT_SECRET=\"" + encodedSecret + "\"\n");
    }
} 