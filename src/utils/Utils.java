package utils;

import digests.MessageDigestWrapper;
import prngs.SecureRandomWrapper;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;
import java.util.HexFormat;

public class Utils {

    /*
     * Method to convert a String into a byte array.
     */
    public static byte[] toByteArray(String input) {

        return input.getBytes();

    }

    /*
     * Method to convert a byte array into a hex string.
     */
    public static String toHexString(byte[] input) {

        return HexFormat.of().formatHex(input);

    }

    /*
     * Method to convert a hex string into a byte array.
     */
    public static byte[] fromHexString(String input) {

        return HexFormat.of().parseHex(input);

    }

    public static String generateRandomKey(MessageDigestWrapper messageDigestWrapper, SecureRandomWrapper secureRandomWrapper) {
        return Utils.toHexString(messageDigestWrapper.computeDigest((byte) secureRandomWrapper.getRandomInt()));
    }

    public static String encryptMessage(String message, String key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(fromHexString(key), "AES");

        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        String base64Message = Base64.getEncoder().encodeToString(message.getBytes(StandardCharsets.UTF_8));
        byte[] messageBytes = base64Message.getBytes(StandardCharsets.UTF_8);

        byte[] encryptedBytes = cipher.doFinal(messageBytes);
        return toHexString(encryptedBytes);
    }

    public static String decryptMessage(String message, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(fromHexString(key), "AES");
        cipher.init(Cipher.DECRYPT_MODE, secretKey);

        byte[] encryptedBytes = fromHexString(message);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        String decodedMessage = new String(decryptedBytes, StandardCharsets.UTF_8);
        byte[] decodedBytes = Base64.getDecoder().decode(decodedMessage);
        return new String(decodedBytes, StandardCharsets.UTF_8);
    }



}