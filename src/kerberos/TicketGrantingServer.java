package kerberos;

import digests.MessageDigestWrapper;
import prngs.SecureRandomWrapper;
import utils.EnvLoader;
import utils.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;

public class TicketGrantingServer {
    private static final int PORT = 9001;
    private static String KEY = "";
    private static final Map<String, String> SERVER_KEYS = new HashMap<>();

    private static final String SEPARATOR = "||";
    private static final String SPLIT_SEPARATOR = "\\|\\|";
    private static final int MAX_DURATION = 2 * 60 * 1000; //2 min

    public static void main(String[] args) throws Exception {

        String k_v = EnvLoader.get("K_V");
        KEY = EnvLoader.get("K_TGS");
        if(!Utils.isValid(k_v) || !Utils.isValid(KEY)) {
            System.out.println("Invalid keys");
            System.exit(1);
        }
        SERVER_KEYS.put("s1", k_v);

        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Ticket Granting Server running on port " + PORT);

        while(true) {
            try {
                handleClient(serverSocket.accept());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
    }

    private static void handleClient(Socket socket) throws Exception{
        BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        PrintWriter out = new PrintWriter(socket.getOutputStream(), true);
        System.out.println("Socket initialized to handle request from " + socket.getPort());

        String message_3 = in.readLine();
        System.out.println(message_3);
        String[] parts = message_3.split(SPLIT_SEPARATOR);
        String id_v = parts[0];
        String encryptedTicket = parts[1];
        String encryptedProof = parts[2];

        String ticket = Utils.decryptMessage(encryptedTicket, KEY);
        String[] ticketParts = ticket.split(SPLIT_SEPARATOR);
        String k_ct = ticketParts[0];
        String id = ticketParts[1];
        String ad_c = ticketParts[2];
        long t2 = Long.parseLong(ticketParts[3]);
        long d_t2 = Long.parseLong(ticketParts[4]);

        String proof = Utils.decryptMessage(encryptedProof, k_ct);
        long t3 = Long.parseLong(proof.split(SPLIT_SEPARATOR)[2]);

        //check that t3 <= t2+d_t2
        if (t3 > t2 + d_t2) {
            out.println("ERROR: Timeout.");
            socket.close();
            return;
        }

        String k_v = SERVER_KEYS.getOrDefault(id_v, "");
        if(k_v.isEmpty()) {
            out.println("ERROR: Server not found.");
            socket.close();
            return;
        }

        // Step 4: TGS->C: E_K_CT(K_CV || ID_V || T4 || E_K_V(K_CV||ID||AD_C||T4||D_T4) )
        SecureRandomWrapper secureRandomWrapper = new SecureRandomWrapper("SHA1PRNG");
        secureRandomWrapper.changeSeed(123456);
        MessageDigestWrapper messageDigestWrapper = new MessageDigestWrapper("SHA-256");

        String k_cv = Utils.generateRandomKey(messageDigestWrapper, secureRandomWrapper);
        String t4 = String.valueOf(System.currentTimeMillis());
        String d_t4 = String.valueOf(MAX_DURATION);
        String serverTicket = String.join(SEPARATOR, k_cv, id, ad_c, t4, d_t4);
        String encrypted_serverTicket = Utils.encryptMessage(serverTicket, k_v);
        String message4 = String.join(SEPARATOR, k_cv, id_v, t4, encrypted_serverTicket);
        String encrypted_message4 = Utils.encryptMessage(message4, k_ct);

        out.println(encrypted_message4);

        if(!socket.isClosed()) {
            socket.close();
        }
    }
}
