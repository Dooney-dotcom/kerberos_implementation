package kerberos;

import digests.MessageDigestWrapper;
import prngs.SecureRandomWrapper;
import utils.Utils;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.SecretKeySpec;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

public class AuthenticationServer {
    private static final int PORT = 9000;
    private static final Map<String, String> USERS_MAP = new HashMap<>();
    private static final Map<String, String> TGS_MAP = new HashMap<>();
    private static final int MAX_DURATION = 30*60*1000;
    private static final String ENCRYPTION_ALGORITHM = "AES";
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String KEY_SIZE = "256";
    private static final String SEPARATOR = "||";

    private static SecureRandomWrapper secureRandomWrapper;
    private static MessageDigestWrapper messageDigestWrapper;

    public static void main(String[] args) throws Exception {
        initDataStructures();

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Authentication Server running on port " + PORT);

        secureRandomWrapper = new SecureRandomWrapper("SHA1PRNG");
        secureRandomWrapper.changeSeed(123456);
        messageDigestWrapper = new MessageDigestWrapper("SHA-256");

        while(true) {
            Socket socket = serverSocket.accept();
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
            System.out.println("Socket initialized to handle request from " + socket.getPort());

            // Step 1: C->AS : ID||AD_C||ID_TGS||T1
            String line = in.readLine();

            String[] parts = line.split("\\|\\|");

            if(parts.length != 4) {
                out.println("Error: Invalid request format. Expected 4 parts.");
                socket.close();
                continue;
            }

            String id = parts[0];
            String ad_c = parts[1];
            String id_tgs = parts[2];
            String t1 = parts[3];

            // Verifica timestamp con finestra temporale di 2 minuti
            boolean isValidTimestamp = verifyTimestamp(t1);
            if (!isValidTimestamp) {
                out.println("Error: Invalid timestamp.");
                socket.close();
                continue;
            }

            String password_hash = USERS_MAP.getOrDefault(id, "");
            if(password_hash.isEmpty()) {
                out.println("Error: User not found.");
                socket.close();
                continue;
            }

            // Step 2: AS->C : E_PSW(K_CT||ID_TGS||T2||D_T2||E_K_TGS(K_CT||ID||AD_C||T2||DT2))
            String t2 = String.valueOf(System.currentTimeMillis());
            String d_t2 = String.valueOf(MAX_DURATION);
            String k_tgs = TGS_MAP.getOrDefault(id_tgs, "");
            String k_ct = Utils.generateRandomKey(messageDigestWrapper, secureRandomWrapper);
            if (k_ct.isEmpty()) {
                out.println("Error: TGS not found.");
                socket.close();
                continue;
            }
            String ticket = k_ct + SEPARATOR + id + SEPARATOR + ad_c + SEPARATOR + t2 + SEPARATOR + d_t2;
            System.out.println(ticket);
            String encryptedTicket = Utils.encryptMessage(ticket, k_tgs);
            String message = k_ct + SEPARATOR + id_tgs + SEPARATOR + t2 + SEPARATOR + d_t2 + SEPARATOR + encryptedTicket;
            System.out.println(message);
            String encryptedMessage = Utils.encryptMessage(message, password_hash);

            out.println(encryptedMessage);
            socket.close();
        }
    }

    private static void initDataStructures() {
        // Per semplicità, hardcoded
        USERS_MAP.put("mario_rossi", "5e884898da28047151d0e56f8dc6292773603d0d4c1b2a1c6f7b8c9e2f3a4b5c");
        USERS_MAP.put("luigi_verdi", "6f1ed002ab5595859014ebf0951522d9b3c3e5a0b8c7e8d1b2c3d4e5f6a7b8c9");
        USERS_MAP.put("anna_bianchi", "7c6a180b36896a0a8c02787eeafb0e4c3d2f1e2b3c4d5e6f7a8b9c0d1e2f3a4b");
        USERS_MAP.put("giovanni_neri", "8d9f1e2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0");
        USERS_MAP.put("francesca_gialli", "9e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1");
        USERS_MAP.put("alessandro_rossi", "1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2");
        USERS_MAP.put("daniele_buono", "d0d561fce7bcf926a4819899b3a2f8c7032db4963b90ab51a9282acde63ffbf3"); // psw: Daniele12

        TGS_MAP.put("tgs1", "9af61dd627ebdd84311c3891b53d3eaf620399f7bb087040971f239acf1b2398");
        TGS_MAP.put("tgs2", "e70307e0b7660d30f1b94063f13aa009445f9a645feb5e4b0a8ed90fb33adc76");
    }

    private static boolean verifyTimestamp(String timestamp) {
        long current = System.currentTimeMillis();
        long received = Long.parseLong(timestamp);
        long twoMinutesInMillis = 2 * 60 * 1000;

        if (Math.abs(current - received) > twoMinutesInMillis) {
            return false;
        }

        return true;
    }


}
