package kerberos;

import utils.EnvLoader;
import utils.Utils;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.MessageDigest;
import java.util.Objects;

public class EchoServer {
    private static final int PORT = 9002;
    private static final String SEPARATOR = "||";
    private static final String SPLIT_SEPARATOR = "\\|\\|";
    private static String KV;

    public static void main(String[] args) throws Exception {
        KV = EnvLoader.get("K_V");
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Echo Server running on port " + PORT);

            while (true) {
                try {
                    handleClient(serverSocket.accept());
                } catch (Exception e) {
                    System.err.println("Client error: " + e.getMessage());
                }
            }
        }
    }

    private static void handleClient(Socket socket) throws Exception {
        System.out.println("Handling client from port " + socket.getPort());

        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

        String message5 = in.readLine();
        if (message5 == null) return;

        String[] parts = message5.split(SPLIT_SEPARATOR);
        if (parts.length < 2) {
            out.println("ERROR: Malformed message5");
            socket.close();
            return;
        }

        String encryptedKeyMessage = parts[0];
        String encryptedTicket = parts[1];

        String keyMessage = Utils.decryptMessage(encryptedKeyMessage, KV);
        parts = keyMessage.split(SPLIT_SEPARATOR);
        String k_cv = parts[0], id = parts[1], ad_c = parts[2];
        long t4 = Long.parseLong(parts[3]);
        long duration = Long.parseLong(parts[4]);

        String ticket = Utils.decryptMessage(encryptedTicket, k_cv);
        parts = ticket.split(SPLIT_SEPARATOR);
        long t5 = Long.parseLong(parts[2]);

        if (!isTimestampValid(t4, duration, t5)) {
            out.println("ERROR: Timeout.");
            socket.close();
            return;
        }

        // STEP 6: V->C: E_K_CV(T5+1)
        out.println(Utils.encryptMessage(String.valueOf(t5 + 1), k_cv));

        // STEP 7: C->V: E_K_CV(ID||AD_C||TIMESTAMP||PAYLOAD)||H(ID||AD_C||TIMESTAMP||PAYLOAD)
        while (true) {
            String request = in.readLine();
            if (request == null || request.startsWith("ERROR")) break;

            String[] split = request.split(SPLIT_SEPARATOR);
            if (split.length != 2) {
                out.println("ERROR: Malformed request.");
                break;
            }

            String encryptedPayload = split[0];
            String receivedDigest = split[1];

            String decryptedPayload = Utils.decryptMessage(encryptedPayload, k_cv);

            if (!verifyDigest(decryptedPayload, receivedDigest)) {
                out.println("ERROR: Digest mismatch.");
                break;
            }

            parts = decryptedPayload.split(SPLIT_SEPARATOR);
            String reqId = parts[0];
            String reqAd = parts[1];
            long reqTimestamp = Long.parseLong(parts[2]);
            String payload = parts[3];

            if (!Objects.equals(reqId, id) || !Objects.equals(reqAd, ad_c)) {
                out.println("ERROR: Client info mismatch.");
                break;
            }

            if (!isTimestampValid(t5, duration, reqTimestamp)) {
                out.println("ERROR: Timestamp expired.");
                break;
            }

            appendToFile("result.txt", payload);
            out.println("OK");
        }

        socket.close();
    }

    private static boolean isTimestampValid(long start, long duration, long target) {
        return target <= (start + duration);
    }

    private static boolean verifyDigest(String message, String expectedDigest) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] computed = digest.digest(Utils.toByteArray(message));
        return Utils.toHexString(computed).equals(expectedDigest);
    }

    private static void appendToFile(String filename, String content) {
        try (FileWriter writer = new FileWriter(filename, true)) {
            writer.write(content + "\n");
        } catch (IOException e) {
            System.err.println("File writing failed: " + e.getMessage());
        }
    }
}
