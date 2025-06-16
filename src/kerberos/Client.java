package kerberos;

import utils.Utils;
import java.io.*;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Client {
    private static final int AUTHENTICATION_SERVER_PORT = 9000;
    private static final int TICKET_GRANTING_SERVER_PORT = 9001;
    private static final int ECHO_SERVER_PORT = 9002;
    private static final String SEPARATOR = "||";
    private static final String SPLIT_SEPARATOR = "\\|\\|";

    private static String authServer, tgs, echoServer;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        clientInitialization(args);

        Scanner scanner = new Scanner(System.in);
        String id = prompt("Username", "admin", scanner);
        String id_tgs = prompt("ID TGS", "tgs1", scanner);
        if(!id_tgs.equals("tgs1")){
            System.out.println("Invalid argument provided");
            System.exit(1);
        }

        try {
            Socket socket = new Socket(authServer, AUTHENTICATION_SERVER_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // Communication with authentication server
            // STEP 1: C->AD: ID||AD_C||ID_TGS||T1
            String ad_c = socket.getLocalAddress().toString();
            String t1 = String.valueOf(System.currentTimeMillis());
            String message1 = String.join(SEPARATOR, id, ad_c, id_tgs, t1);
            System.out.println("Message 1: " + message1);
            out.println(message1);

            // Step 2: AS->C : E_PSW(K_CT||ID_TGS||T2||D_T2||E_K_TGS(K_CT||ID||AD_C||T2||DT2))
            String encrypted_message2 = in.readLine();
            closeSocket(socket);
            if (encrypted_message2.startsWith("ERROR")) {
                System.out.println("Server response: " + encrypted_message2);
                return;
            }

            System.out.println("Message 2: " + encrypted_message2);
            String psw = prompt("Password", "password used to generate S_K in generate_env.sh", scanner);
            psw = Utils.getMessageDigest(psw, "SHA-256");
            String message = Utils.decryptMessage(encrypted_message2, psw);
            String[] parts = message.split(SPLIT_SEPARATOR);
            String k_ct = parts[0];
            id_tgs = parts[1];
            String t2 = parts[2];
            String d_t2 = parts[3];
            String encryptedTicket = parts[4];

            // Communication with Ticket Granting Server
            // Step 3: C->TGS ID_V || E_K_TGS(K_CT||ID||AD_C||T2||DT2) || E_KCT(ID||AD_C||T3)

            String id_v = prompt("ID Server", "s1", scanner);
            if(!id_v.equals("s1")) {
                System.out.println("Invalid argument provided");
                System.exit(1);
            }

            String t3 = String.valueOf(System.currentTimeMillis());
            String proof = String.join(SEPARATOR, id, ad_c, t3);
            String encryptedProof = Utils.encryptMessage(proof, k_ct);

            socket = new Socket(tgs, TICKET_GRANTING_SERVER_PORT);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            String message3 = String.join(SEPARATOR, id_v, encryptedTicket, encryptedProof);
            System.out.println("Message 3: " + message3);
            out.println(message3);

            // Step 4: TGS->C: E_K_CT(K_CV || ID_V || T4 || E_K_V(K_CV||ID||AD_C||T4||D_T4) )
            String encrypted_message4 = in.readLine();
            closeSocket(socket);
            if (encrypted_message4.startsWith("ERROR")) {
                System.out.println("Server response: " + encrypted_message4);
                return;
            }

            String message_step4 = Utils.decryptMessage(encrypted_message4, k_ct);
            System.out.println("Message 4: " + message_step4);
            parts = message_step4.split(SPLIT_SEPARATOR);

            String k_cv = parts[0];
            id_v = parts[1];
            String t4 = parts[2];
            String e_kv = parts[3];

            //Step 5: C->V: E_KV(K_CV || ID || AD_C || T4 || DT4) || E_K_CV(ID||AD_C||T5)
            String t5 = String.valueOf(System.currentTimeMillis());
            String proof5 = String.join(SEPARATOR, id, ad_c, t5);
            String encrypted_proof5 = Utils.encryptMessage(proof5, k_cv);
            String message5 = String.join(SEPARATOR, e_kv, encrypted_proof5);

            socket = new Socket(echoServer, ECHO_SERVER_PORT);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            System.out.println("Message 5: " + message5);
            out.println(message5);

            // STEP 6: V->C: E_K_CV(T5+1)
            String encrypted_message6 = in.readLine();
            if (encrypted_message6.startsWith("ERROR")) {
                System.out.println("Server response: " + encrypted_message6);
                return;
            }

            String message6 = Utils.decryptMessage(encrypted_message6, k_cv);
            long t5Long = Long.parseLong(t5) + 1;
            if(String.valueOf(t5Long).equals(message6)) {
                System.out.println("!!! AUTHENTICATION COMPLETED !!!");
                System.out.println("User can start using ECHO SERVER");
            } else {
                System.out.println("Error: timestamp do not correspond");
                System.out.println(String.valueOf(t5Long));
                System.out.println(message6);
                out.println("ERROR");
                closeSocket(socket);
            }

            // STEP 7: C->V: E_K_CV(ID||AD_C||TIMESTAMP||PAYLOAD)||H(ID||AD_C||TIMESTAMP||PAYLOAD)
            System.out.println("Contenuto da scrivere sul server: ");
            String payload = scanner.nextLine();
            do {
                String timestamp = String.valueOf(System.currentTimeMillis());
                String request = String.join(SEPARATOR, id, ad_c, timestamp, payload);
                String encryptedRequest = Utils.encryptMessage(request, k_cv);
                String requestDigest = Utils.getMessageDigest(request, "SHA-256");
                message = String.join(SEPARATOR, encryptedRequest, requestDigest);
                System.out.println(message);
                out.println(message);

                String response = in.readLine();
                System.out.println("Operation result: " + response);
                if(response.startsWith("ERROR")) {
                    return;
                }

                System.out.println("Contenuto da scrivere sul server (o STOP): ");
                payload = scanner.nextLine();

            } while(!payload.equals("STOP"));

            closeSocket(socket);

        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }

    private static void closeSocket(Socket socket) throws IOException {
        if(socket.isClosed()) {
            return;
        }

        socket.close();
    }

    private static void clientInitialization(String[] args) {
        if (args.length != 3) {
            System.out.println("ERROR: invalid number of arguments.");
            System.out.println("Correct usage: java -cp src kerberos.Client <authserver> <tgs> <echoserver>");
            System.exit(1);
        }

        authServer = args[0];
        tgs = args[1];
        echoServer = args[2];
    }

    private static String prompt(String message, String hint, Scanner scanner) {
        System.out.println(message + " (hint: " + hint + ")");
        String param = scanner.nextLine();

        if(param == null || param.isEmpty()) {
            System.out.println("Invalid param provided");
            System.exit(1);
        }

        return param;
    }
}
