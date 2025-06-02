package com.example.SmartStego.utils;

import org.apache.commons.codec.binary.Base64;
import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;

@Component
public class CryptoUtils {

    private static final String AES_ALGORITHM = "AES";
    private static final String AES_GCM_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final String AES_ECB_TRANSFORMATION = "AES/ECB/PKCS5Padding";
    private static final int GCM_IV_LENGTH = 12;
    private static final int GCM_TAG_LENGTH = 16;
    private static final int KEY_LENGTH = 32; // 256-bit key
    private static final int PBKDF2_ITERATIONS = 10000;

    /**
     * Generate AES-256 key from password using SHA-256
     * For better security, consider using PBKDF2 with salt
     */
    public SecretKeySpec generateKeyFromPassword(String password) {
        try {
            MessageDigest sha = MessageDigest.getInstance("SHA-256");
            byte[] key = sha.digest(password.getBytes(StandardCharsets.UTF_8));
            // Use full 256-bit key
            return new SecretKeySpec(key, AES_ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException("Error generating key from password", e);
        }
    }

    /**
     * Generate AES key from password with salt using PBKDF2 (more secure)
     * This method is more secure but requires storing the salt
     */
    public SecretKeySpec generateKeyFromPasswordWithSalt(String password, byte[] salt) {
        try {
            javax.crypto.spec.PBEKeySpec spec = new javax.crypto.spec.PBEKeySpec(
                    password.toCharArray(), salt, PBKDF2_ITERATIONS, KEY_LENGTH * 8);
            javax.crypto.SecretKeyFactory factory = javax.crypto.SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            byte[] key = factory.generateSecret(spec).getEncoded();
            return new SecretKeySpec(key, AES_ALGORITHM);
        } catch (Exception e) {
            throw new RuntimeException("Error generating key from password with salt", e);
        }
    }

    /**
     * Encrypt text using AES-GCM (more secure than ECB)
     * GCM provides both confidentiality and authenticity
     */
    public String encryptGCM(String plainText, String password) {
        try {
            SecretKeySpec secretKey = generateKeyFromPassword(password);
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);

            // Generate random IV
            byte[] iv = new byte[GCM_IV_LENGTH];
            new SecureRandom().nextBytes(iv);
            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);

            cipher.init(Cipher.ENCRYPT_MODE, secretKey, parameterSpec);
            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));

            // Combine IV and encrypted data
            byte[] encryptedWithIv = new byte[GCM_IV_LENGTH + encryptedBytes.length];
            System.arraycopy(iv, 0, encryptedWithIv, 0, GCM_IV_LENGTH);
            System.arraycopy(encryptedBytes, 0, encryptedWithIv, GCM_IV_LENGTH, encryptedBytes.length);

            return Base64.encodeBase64String(encryptedWithIv);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting text with GCM", e);
        }
    }

    /**
     * Decrypt text using AES-GCM
     */
    public String decryptGCM(String encryptedText, String password) {
        try {
            SecretKeySpec secretKey = generateKeyFromPassword(password);
            Cipher cipher = Cipher.getInstance(AES_GCM_TRANSFORMATION);

            byte[] encryptedWithIv = Base64.decodeBase64(encryptedText);

            // Extract IV and encrypted data
            byte[] iv = Arrays.copyOfRange(encryptedWithIv, 0, GCM_IV_LENGTH);
            byte[] encrypted = Arrays.copyOfRange(encryptedWithIv, GCM_IV_LENGTH, encryptedWithIv.length);

            GCMParameterSpec parameterSpec = new GCMParameterSpec(GCM_TAG_LENGTH * 8, iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, parameterSpec);

            byte[] decryptedBytes = cipher.doFinal(encrypted);
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting text with GCM: Invalid password or corrupted data", e);
        }
    }

    /**
     * Encrypt text using AES-ECB (backward compatibility)
     * Note: ECB mode is less secure, use GCM when possible
     */
    public String encrypt(String plainText, String password) {
        try {
            SecretKeySpec secretKey = generateKeyFromPassword(password);
            Cipher cipher = Cipher.getInstance(AES_ECB_TRANSFORMATION);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);

            byte[] encryptedBytes = cipher.doFinal(plainText.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeBase64String(encryptedBytes);
        } catch (Exception e) {
            throw new RuntimeException("Error encrypting text", e);
        }
    }

    /**
     * Decrypt text using AES-ECB (backward compatibility)
     */
    public String decrypt(String encryptedText, String password) {
        try {
            SecretKeySpec secretKey = generateKeyFromPassword(password);
            Cipher cipher = Cipher.getInstance(AES_ECB_TRANSFORMATION);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);

            byte[] decryptedBytes = cipher.doFinal(Base64.decodeBase64(encryptedText));
            return new String(decryptedBytes, StandardCharsets.UTF_8);
        } catch (Exception e) {
            throw new RuntimeException("Error decrypting text: Invalid password or corrupted data", e);
        }
    }

    /**
     * Generate a cryptographically secure random password
     */
    public String generateRandomPassword(int length) {
        if (length < 8) {
            throw new IllegalArgumentException("Password length should be at least 8 characters");
        }

        String upperCase = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
        String lowerCase = "abcdefghijklmnopqrstuvwxyz";
        String digits = "0123456789";
        String special = "!@#$%^&*()-_=+[]{}|;:,.<>?";
        String allChars = upperCase + lowerCase + digits + special;

        SecureRandom random = new SecureRandom();
        StringBuilder password = new StringBuilder();

        // Ensure at least one character from each category
        password.append(upperCase.charAt(random.nextInt(upperCase.length())));
        password.append(lowerCase.charAt(random.nextInt(lowerCase.length())));
        password.append(digits.charAt(random.nextInt(digits.length())));
        password.append(special.charAt(random.nextInt(special.length())));

        // Fill the rest randomly
        for (int i = 4; i < length; i++) {
            password.append(allChars.charAt(random.nextInt(allChars.length())));
        }

        // Shuffle the password to avoid predictable patterns
        return shuffleString(password.toString(), random);
    }

    /**
     * Generate a random salt for PBKDF2
     */
    public byte[] generateSalt() {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return salt;
    }

    /**
     * Hash a password using SHA-256 (for verification purposes)
     */
    public String hashPassword(String password) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(password.getBytes(StandardCharsets.UTF_8));
            return Base64.encodeBase64String(hash);
        } catch (Exception e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    /**
     * Verify if a password matches its hash
     */
    public boolean verifyPassword(String password, String hash) {
        return hashPassword(password).equals(hash);
    }

    /**
     * Check password strength
     */
    public PasswordStrength checkPasswordStrength(String password) {
        if (password == null || password.length() < 8) {
            return PasswordStrength.WEAK;
        }

        boolean hasUpper = password.chars().anyMatch(Character::isUpperCase);
        boolean hasLower = password.chars().anyMatch(Character::isLowerCase);
        boolean hasDigit = password.chars().anyMatch(Character::isDigit);
        boolean hasSpecial = password.chars().anyMatch(ch -> "!@#$%^&*()-_=+[]{}|;:,.<>?".indexOf(ch) >= 0);

        int criteriaCount = (hasUpper ? 1 : 0) + (hasLower ? 1 : 0) + (hasDigit ? 1 : 0) + (hasSpecial ? 1 : 0);

        if (password.length() >= 12 && criteriaCount >= 3) {
            return PasswordStrength.STRONG;
        } else if (password.length() >= 8 && criteriaCount >= 2) {
            return PasswordStrength.MEDIUM;
        } else {
            return PasswordStrength.WEAK;
        }
    }

    /**
     * Utility method to shuffle a string
     */
    private String shuffleString(String string, SecureRandom random) {
        char[] characters = string.toCharArray();
        for (int i = characters.length - 1; i > 0; i--) {
            int randomIndex = random.nextInt(i + 1);
            char temp = characters[i];
            characters[i] = characters[randomIndex];
            characters[randomIndex] = temp;
        }
        return new String(characters);
    }

    /**
     * Enum for password strength levels
     */
    public enum PasswordStrength {
        WEAK("Weak - Use a stronger password"),
        MEDIUM("Medium - Consider adding more complexity"),
        STRONG("Strong - Good password security");

        private final String description;

        PasswordStrength(String description) {
            this.description = description;
        }

        public String getDescription() {
            return description;
        }
    }

    /**
     * Generate a secure random key for testing purposes
     */
    public String generateSecureKey() {
        byte[] key = new byte[32]; // 256-bit key
        new SecureRandom().nextBytes(key);
        return Base64.encodeBase64String(key);
    }

    /**
     * Timing-safe string comparison to prevent timing attacks
     */
    public boolean constantTimeEquals(String a, String b) {
        if (a == null || b == null) {
            return a == b;
        }

        if (a.length() != b.length()) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length(); i++) {
            result |= a.charAt(i) ^ b.charAt(i);
        }

        return result == 0;
    }
}