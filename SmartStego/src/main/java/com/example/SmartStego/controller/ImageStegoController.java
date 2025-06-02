package com.example.SmartStego.controller;
import com.example.SmartStego.service.ImageStegoService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ByteArrayResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.*;

@Controller
public class ImageStegoController {

    @Autowired
    private ImageStegoService imageService;

    // Thread pool for handling operations with timeout
    private final ExecutorService executorService = Executors.newCachedThreadPool();
    private static final int OPERATION_TIMEOUT_SECONDS = 30;

    @GetMapping("/")
    public String index() {
        return "index";
    }

    @GetMapping("/image")
    public String imagePage() {
        return "image";
    }

    @PostMapping("/hide")
    @ResponseBody
    public ResponseEntity<?> hideMessage(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("message") String message,
            @RequestParam("password") String password) {

        try {
            if (imageFile.isEmpty()) {
                return ResponseEntity.badRequest().body("Please select an image file");
            }

            if (message.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Please enter a message to hide");
            }

            if (password.trim().isEmpty()) {
                return ResponseEntity.badRequest().body("Please enter a password");
            }

            // Validate file type
            String contentType = imageFile.getContentType();
            if (contentType == null || (!contentType.startsWith("image/"))) {
                return ResponseEntity.badRequest().body("Please upload a valid image file");
            }

            // Validate file size (max 10MB)
            if (imageFile.getSize() > 10 * 1024 * 1024) {
                return ResponseEntity.badRequest().body("Image file too large. Maximum size is 10MB");
            }

            // Check image capacity with timeout
            Future<Integer> capacityFuture = executorService.submit(() ->
                    imageService.calculateCapacity(imageFile.getBytes()));

            int capacity;
            try {
                capacity = capacityFuture.get(10, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                capacityFuture.cancel(true);
                return ResponseEntity.badRequest().body("Image processing timeout - try a smaller image");
            }

            if (message.length() > capacity) {
                return ResponseEntity.badRequest()
                        .body("Message too long. Maximum capacity: " + capacity + " characters");
            }

            // Hide message with timeout
            Future<byte[]> hideFuture = executorService.submit(() ->
                    imageService.hideMessage(imageFile.getBytes(), message, password));

            byte[] stegoImage;
            try {
                stegoImage = hideFuture.get(OPERATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                hideFuture.cancel(true);
                return ResponseEntity.badRequest().body("Operation timeout - try a smaller message or image");
            }

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.IMAGE_PNG);
            headers.setContentDispositionFormData("attachment", "stego_image.png");

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(new ByteArrayResource(stegoImage));

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            return ResponseEntity.badRequest().body("Error processing image: " + cause.getMessage());
        } catch (Exception e) {
            return ResponseEntity.badRequest().body("Error processing image: " + e.getMessage());
        }
    }

    @PostMapping("/extract")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> extractMessage(
            @RequestParam("image") MultipartFile imageFile,
            @RequestParam("password") String password) {

        Map<String, Object> response = new HashMap<>();

        try {
            if (imageFile.isEmpty()) {
                response.put("success", false);
                response.put("message", "Please select an image file");
                return ResponseEntity.badRequest().body(response);
            }

            if (password.trim().isEmpty()) {
                response.put("success", false);
                response.put("message", "Please enter a password");
                return ResponseEntity.badRequest().body(response);
            }

            // Validate file type
            String contentType = imageFile.getContentType();
            if (contentType == null || (!contentType.startsWith("image/"))) {
                response.put("success", false);
                response.put("message", "Please upload a valid image file");
                return ResponseEntity.badRequest().body(response);
            }

            // Validate file size (max 10MB)
            if (imageFile.getSize() > 10 * 1024 * 1024) {
                response.put("success", false);
                response.put("message", "Image file too large. Maximum size is 10MB");
                return ResponseEntity.badRequest().body(response);
            }

            // Check if image has hidden message with timeout
            Future<Boolean> hasMessageFuture = executorService.submit(() ->
                    imageService.hasHiddenMessage(imageFile.getBytes()));

            boolean hasHiddenMessage;
            try {
                hasHiddenMessage = hasMessageFuture.get(15, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                hasMessageFuture.cancel(true);
                response.put("success", false);
                response.put("message", "Image analysis timeout - image may be too large or corrupted");
                return ResponseEntity.badRequest().body(response);
            }

            if (!hasHiddenMessage) {
                response.put("success", false);
                response.put("message", "No hidden message found in this image");
                return ResponseEntity.ok(response);
            }

            // Extract message with timeout
            Future<String> extractFuture = executorService.submit(() ->
                    imageService.extractMessage(imageFile.getBytes(), password));

            String extractedMessage;
            try {
                extractedMessage = extractFuture.get(OPERATION_TIMEOUT_SECONDS, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                extractFuture.cancel(true);
                response.put("success", false);
                response.put("message", "Extraction timeout - image may be corrupted or password incorrect");
                return ResponseEntity.badRequest().body(response);
            }

            response.put("success", true);
            response.put("message", "Message extracted successfully");
            response.put("extractedMessage", extractedMessage);

            return ResponseEntity.ok(response);

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            response.put("success", false);
            response.put("message", "Error extracting message: " + cause.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Error extracting message: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    @PostMapping("/check-capacity")
    @ResponseBody
    public ResponseEntity<Map<String, Object>> checkCapacity(@RequestParam("image") MultipartFile imageFile) {
        Map<String, Object> response = new HashMap<>();

        try {
            if (imageFile.isEmpty()) {
                response.put("success", false);
                response.put("message", "Please select an image file");
                return ResponseEntity.badRequest().body(response);
            }

            // Validate file type
            String contentType = imageFile.getContentType();
            if (contentType == null || (!contentType.startsWith("image/"))) {
                response.put("success", false);
                response.put("message", "Please upload a valid image file");
                return ResponseEntity.badRequest().body(response);
            }

            // Calculate capacity with timeout
            Future<Integer> capacityFuture = executorService.submit(() ->
                    imageService.calculateCapacity(imageFile.getBytes()));

            Future<Boolean> hasMessageFuture = executorService.submit(() ->
                    imageService.hasHiddenMessage(imageFile.getBytes()));

            int capacity;
            boolean hasHiddenMessage;

            try {
                capacity = capacityFuture.get(10, TimeUnit.SECONDS);
                hasHiddenMessage = hasMessageFuture.get(10, TimeUnit.SECONDS);
            } catch (TimeoutException e) {
                capacityFuture.cancel(true);
                hasMessageFuture.cancel(true);
                response.put("success", false);
                response.put("message", "Image analysis timeout - try a smaller image");
                return ResponseEntity.badRequest().body(response);
            }

            response.put("success", true);
            response.put("capacity", capacity);
            response.put("hasHiddenMessage", hasHiddenMessage);

            return ResponseEntity.ok(response);

        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            response.put("success", false);
            response.put("message", "Error checking image: " + cause.getMessage());
            return ResponseEntity.badRequest().body(response);
        } catch (Exception e) {
            response.put("success", false);
            response.put("message", "Error checking image: " + e.getMessage());
            return ResponseEntity.badRequest().body(response);
        }
    }

    // Cleanup method (optional - you might want to add this to a @PreDestroy method)
    public void shutdown() {
        executorService.shutdown();
        try {
            if (!executorService.awaitTermination(5, TimeUnit.SECONDS)) {
                executorService.shutdownNow();
            }
        } catch (InterruptedException e) {
            executorService.shutdownNow();
        }
    }
}