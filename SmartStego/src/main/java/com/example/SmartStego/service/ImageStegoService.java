package com.example.SmartStego.service;

import com.example.SmartStego.utils.CryptoUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.imageio.ImageIO;
import java.awt.image.BufferedImage;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;

@Service
public class ImageStegoService {

    @Autowired
    private CryptoUtils cryptoUtils;

    private static final String DELIMITER = "###END###";
    private static final int MAX_EXTRACTION_ATTEMPTS = 1000000; // Prevent infinite loops

    /**
     * Hide encrypted text in image using LSB steganography
     */
    public byte[] hideMessage(byte[] imageBytes, String message, String password) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));

        // Convert to RGB if not already (important for JPEGs)
        BufferedImage rgbImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
        rgbImage.getGraphics().drawImage(image, 0, 0, null);
        image = rgbImage;

        // Encrypt the message
        String encryptedMessage = cryptoUtils.encrypt(message, password);
        String messageWithDelimiter = encryptedMessage + DELIMITER;

        // Convert message to binary
        StringBuilder binaryMessage = new StringBuilder();
        for (char c : messageWithDelimiter.toCharArray()) {
            binaryMessage.append(String.format("%8s", Integer.toBinaryString(c)).replace(' ', '0'));
        }

        // Check if image can hold the message
        int totalPixels = image.getWidth() * image.getHeight();
        if (binaryMessage.length() > totalPixels * 3) {
            throw new RuntimeException("Image too small to hold the message");
        }

        // Hide message in LSB of RGB values
        int messageIndex = 0;

        for (int y = 0; y < image.getHeight() && messageIndex < binaryMessage.length(); y++) {
            for (int x = 0; x < image.getWidth() && messageIndex < binaryMessage.length(); x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Modify LSB of red channel
                if (messageIndex < binaryMessage.length()) {
                    r = (r & 0xFE) | Character.getNumericValue(binaryMessage.charAt(messageIndex++));
                }

                // Modify LSB of green channel
                if (messageIndex < binaryMessage.length()) {
                    g = (g & 0xFE) | Character.getNumericValue(binaryMessage.charAt(messageIndex++));
                }

                // Modify LSB of blue channel
                if (messageIndex < binaryMessage.length()) {
                    b = (b & 0xFE) | Character.getNumericValue(binaryMessage.charAt(messageIndex++));
                }

                int newRgb = (r << 16) | (g << 8) | b;
                image.setRGB(x, y, newRgb);
            }
        }

        // Convert image back to bytes - ALWAYS use PNG to preserve LSB data
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ImageIO.write(image, "PNG", baos);
        return baos.toByteArray();
    }

    /**
     * Extract and decrypt hidden message from image (FIXED VERSION)
     */
    public String extractMessage(byte[] imageBytes, String password) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));

        // Convert to RGB if not already
        if (image.getType() != BufferedImage.TYPE_INT_RGB) {
            BufferedImage rgbImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
            rgbImage.getGraphics().drawImage(image, 0, 0, null);
            image = rgbImage;
        }

        StringBuilder binaryMessage = new StringBuilder();
        StringBuilder extractedText = new StringBuilder();
        int bitsProcessed = 0;
        boolean delimiterFound = false;

        // Calculate maximum safe extraction limit
        int maxPixels = Math.min(image.getWidth() * image.getHeight(), MAX_EXTRACTION_ATTEMPTS / 3);

        // Extract LSB from each RGB channel
        outerLoop:
        for (int y = 0; y < image.getHeight() && y * image.getWidth() < maxPixels; y++) {
            for (int x = 0; x < image.getWidth() && bitsProcessed < MAX_EXTRACTION_ATTEMPTS; x++) {
                int rgb = image.getRGB(x, y);
                int r = (rgb >> 16) & 0xFF;
                int g = (rgb >> 8) & 0xFF;
                int b = rgb & 0xFF;

                // Extract LSB from each channel
                binaryMessage.append(r & 1);
                binaryMessage.append(g & 1);
                binaryMessage.append(b & 1);
                bitsProcessed += 3;

                // Process every 8 bits (1 byte)
                while (binaryMessage.length() >= 8) {
                    String byteBinary = binaryMessage.substring(0, 8);
                    binaryMessage.delete(0, 8);

                    try {
                        int charValue = Integer.parseInt(byteBinary, 2);
                        // Only process printable characters and common control chars
                        if (charValue >= 0 && charValue <= 255) {
                            char extractedChar = (char) charValue;
                            extractedText.append(extractedChar);

                            // Check for delimiter more efficiently
                            if (extractedText.length() >= DELIMITER.length()) {
                                String recentText = extractedText.substring(
                                        Math.max(0, extractedText.length() - DELIMITER.length() - 50),
                                        extractedText.length()
                                );

                                if (recentText.contains(DELIMITER)) {
                                    delimiterFound = true;
                                    break outerLoop;
                                }
                            }

                            // Prevent memory overflow
                            if (extractedText.length() > 100000) {
                                throw new RuntimeException("Message too long or corrupted - no delimiter found");
                            }
                        }
                    } catch (NumberFormatException e) {
                        // Skip invalid binary sequences
                        continue;
                    }
                }

                // Safety check to prevent infinite processing
                if (bitsProcessed > MAX_EXTRACTION_ATTEMPTS) {
                    throw new RuntimeException("Maximum extraction limit reached - message may be corrupted");
                }
            }
        }

        if (!delimiterFound) {
            throw new RuntimeException("No valid hidden message found - delimiter not detected");
        }

        // Extract the encrypted message (everything before the last occurrence of delimiter)
        String fullExtractedText = extractedText.toString();
        int lastDelimiterIndex = fullExtractedText.lastIndexOf(DELIMITER);

        if (lastDelimiterIndex == -1) {
            throw new RuntimeException("Delimiter parsing error");
        }

        String encryptedMessage = fullExtractedText.substring(0, lastDelimiterIndex);

        if (encryptedMessage.trim().isEmpty()) {
            throw new RuntimeException("No encrypted content found");
        }

        try {
            // Decrypt and return the message
            return cryptoUtils.decrypt(encryptedMessage, password);
        } catch (Exception e) {
            throw new RuntimeException("Failed to decrypt message. Check your password.", e);
        }
    }

    /**
     * Calculate maximum message capacity for an image
     */
    public int calculateCapacity(byte[] imageBytes) throws IOException {
        BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));
        int totalPixels = image.getWidth() * image.getHeight();
        // Each pixel can hold 3 bits (1 bit per RGB channel)
        // Each character needs 8 bits
        return (totalPixels * 3) / 8 - DELIMITER.length() - 50; // Buffer for encryption overhead
    }

    /**
     * Check if image has hidden message (IMPROVED VERSION)
     */
    public boolean hasHiddenMessage(byte[] imageBytes) {
        try {
            BufferedImage image = ImageIO.read(new ByteArrayInputStream(imageBytes));

            // Convert to RGB if needed
            if (image.getType() != BufferedImage.TYPE_INT_RGB) {
                BufferedImage rgbImage = new BufferedImage(image.getWidth(), image.getHeight(), BufferedImage.TYPE_INT_RGB);
                rgbImage.getGraphics().drawImage(image, 0, 0, null);
                image = rgbImage;
            }

            StringBuilder binaryMessage = new StringBuilder();
            StringBuilder currentText = new StringBuilder();

            // Limit search to reasonable amount - check first 10000 pixels max
            int maxPixelsToCheck = Math.min(image.getWidth() * image.getHeight(), 10000);
            int pixelsChecked = 0;

            outerLoop:
            for (int y = 0; y < image.getHeight() && pixelsChecked < maxPixelsToCheck; y++) {
                for (int x = 0; x < image.getWidth() && pixelsChecked < maxPixelsToCheck; x++) {
                    int rgb = image.getRGB(x, y);
                    int r = (rgb >> 16) & 0xFF;
                    int g = (rgb >> 8) & 0xFF;
                    int b = rgb & 0xFF;

                    binaryMessage.append(r & 1);
                    binaryMessage.append(g & 1);
                    binaryMessage.append(b & 1);
                    pixelsChecked++;

                    // Process every complete byte
                    while (binaryMessage.length() >= 8) {
                        String byteBinary = binaryMessage.substring(0, 8);
                        binaryMessage.delete(0, 8);

                        try {
                            int charValue = Integer.parseInt(byteBinary, 2);
                            if (charValue >= 0 && charValue <= 255) {
                                currentText.append((char) charValue);

                                // Check for delimiter
                                if (currentText.toString().contains(DELIMITER)) {
                                    return true;
                                }

                                // Keep only recent characters to prevent memory issues
                                if (currentText.length() > DELIMITER.length() * 3) {
                                    currentText.delete(0, currentText.length() - DELIMITER.length() * 2);
                                }
                            }
                        } catch (NumberFormatException e) {
                            // Skip invalid sequences
                            continue;
                        }
                    }
                }
            }

            return false;

        } catch (Exception e) {
            System.err.println("Error checking for hidden message: " + e.getMessage());
            return false;
        }
    }
}