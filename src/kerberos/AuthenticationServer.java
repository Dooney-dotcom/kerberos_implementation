package kerberos;

import digests.MessageDigestWrapper;
import prngs.SecureRandomWrapper;
import utils.EnvLoader;
import utils.Utils;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
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
                out.println("ERROR: Invalid request format. Expected 4 parts.");
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
                out.println("ERROR: Invalid timestamp.");
                socket.close();
                continue;
            }

            String password_hash = USERS_MAP.getOrDefault(id, "");
            if(password_hash.isEmpty()) {
                out.println("ERROR: User not found.");
                socket.close();
                continue;
            }

            // Step 2: AS->C : E_PSW(K_CT||ID_TGS||T2||D_T2||E_K_TGS(K_CT||ID||AD_C||T2||DT2))
            String t2 = String.valueOf(System.currentTimeMillis());
            String d_t2 = String.valueOf(MAX_DURATION);
            String k_tgs = TGS_MAP.getOrDefault(id_tgs, "");
            String k_ct = Utils.generateRandomKey(messageDigestWrapper, secureRandomWrapper);
            if (k_ct.isEmpty()) {
                out.println("ERROR: TGS not found.");
                socket.close();
                continue;
            }
            String ticket = String.join(SEPARATOR, k_ct, id, ad_c, t2, d_t2);
            System.out.println(ticket);
            String encryptedTicket = Utils.encryptMessage(ticket, k_tgs);
            String message = String.join(SEPARATOR, k_ct, id_tgs, t2, d_t2, encryptedTicket);
            System.out.println(message);
            String encryptedMessage = Utils.encryptMessage(message, password_hash);

            out.println(encryptedMessage);
            socket.close();
        }
    }

    private static void initDataStructures() {
        String k_tgs = EnvLoader.get("K_TGS");
        String s_k = EnvLoader.get("SK");

        if(!Utils.isValid(k_tgs) || !Utils.isValid(s_k)) {
            System.out.println("Invalid keys");
            System.exit(1);
        }

        TGS_MAP.put("tgs1", k_tgs);
        USERS_MAP.put("admin", s_k);
    }

    private static boolean verifyTimestamp(String timestamp) {
        long current = System.currentTimeMillis();
        long received = Long.parseLong(timestamp);
        long twoMinutesInMillis = 2 * 60 * 1000;

        return Math.abs(current - received) <= twoMinutesInMillis;
    }


}
