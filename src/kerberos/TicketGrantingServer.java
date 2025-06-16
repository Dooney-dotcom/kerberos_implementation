package kerberos;

import digests.MessageDigestWrapper;
import prngs.SecureRandomWrapper;
import utils.Utils;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Map;

public class TicketGrantingServer {
    private static final int PORT = 9001;
    private static final String KEY = "9af61dd627ebdd84311c3891b53d3eaf620399f7bb087040971f239acf1b2398";
    private static final Map<String, String> SERVER_KEYS = Map.of("s1", "36f1b05e18373e82f4456847c5f59cd22363d653acf95c1b11f142d927c068d7");

    private static final String SEPARATOR = "||";
    private static final String SPLIT_SEPARATOR = "\\|\\|";
    private static final int MAX_DURATION = 2 * 60 * 1000; //2 min

    public static void main(String[] args) throws Exception {
        ServerSocket serverSocket = new ServerSocket(PORT);
        System.out.println("Ticket Granting Server running on port " + PORT);

        while(true) {
            Socket socket = serverSocket.accept();
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
            String t2 = ticketParts[3];
            String d_t2 = ticketParts[4];

            String proof = Utils.decryptMessage(encryptedProof, k_ct);
            String t3 = proof.split(SPLIT_SEPARATOR)[2];

            //check that t3 <= t2+d_t2
            long t2Long = Long.parseLong(t2);
            long d_t2Long = Long.parseLong(d_t2);
            long t3Long = Long.parseLong(t3);

            if (t3Long > t2Long + d_t2Long) {
                out.println("Error: Timeout.");
                socket.close();
                continue;
            }

            String k_v = SERVER_KEYS.getOrDefault(id_v, "");
            if(k_v.isEmpty()) {
                out.println("Error: Server not found.");
                socket.close();
                continue;
            }

            // Step 4: TGS->C: E_K_CT(K_CV || ID_V || T4 || E_K_V(K_CV||ID||AD_C||T4||D_T4) )
            SecureRandomWrapper secureRandomWrapper = new SecureRandomWrapper("SHA1PRNG");
            secureRandomWrapper.changeSeed(123456);
            MessageDigestWrapper messageDigestWrapper = new MessageDigestWrapper("SHA-256");
            String k_cv = Utils.generateRandomKey(messageDigestWrapper, secureRandomWrapper);
            String t4 = String.valueOf(System.currentTimeMillis());
            String d_t4 = String.valueOf(MAX_DURATION);
            String serverTicket = k_cv + SEPARATOR + id + SEPARATOR + ad_c + SEPARATOR + t4 + SEPARATOR + d_t4;
            String encrypted_serverTicket = Utils.encryptMessage(serverTicket, k_v);
            String message4 = k_cv + SEPARATOR + id_v + SEPARATOR + t4 + SEPARATOR + encrypted_serverTicket;
            String encrypted_message4 = Utils.encryptMessage(message4, k_ct);

            out.println(encrypted_message4);
            socket.close();
        }
    }
}
