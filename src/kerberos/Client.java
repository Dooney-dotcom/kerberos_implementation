package kerberos;

import digests.MessageDigestWrapper;
import utils.Utils;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

public class Client {
    private static final int AUTHENTICATION_SERVER_PORT = 9000;
    private static final int TICKET_GRANTING_SERVER_PORT = 9001;
    private static final int ECHO_SERVER_PORT = 9002;
    private static final String SEPARATOR = "||";
    private static final String SPLIT_SEPARATOR = "\\|\\|";

    public static void main(String[] args) throws NoSuchAlgorithmException {

        if (args.length != 3) {
            System.out.println("Errore: numero errato di argomenti.");
            System.out.println("Utilizzo corretto: java -cp src kerberos.Client <authserver> <tgs> <echoserver>");
            System.exit(1);
        }

        String authserver = args[0];
        String tgs = args[1];
        String echoserver = args[2];

        if (authserver == null || authserver.isEmpty()) {
            System.out.println("Errore: 'authserver' non può essere vuoto.");
            System.exit(1);
        }

        if (tgs == null || tgs.isEmpty()) {
            System.out.println("Errore: 'tgs' non può essere vuoto.");
            System.exit(1);
        }

        if (echoserver == null || echoserver.isEmpty()) {
            System.out.println("Errore: 'echoserver' non può essere vuoto.");
            System.exit(1);
        }

        System.out.println("Connessione a server:");
        System.out.println("AuthServer: " + authserver);
        System.out.println("TGS: " + tgs);
        System.out.println("EchoServer: " + echoserver);

        Scanner scanner = new Scanner(System.in);

        System.out.println("Username: ");
        String id = scanner.nextLine();
        if(id == null || id.isEmpty()) {
            System.out.println("Invalid argument provided");
            System.exit(1);
        }

        System.out.println("Password: ");
        String psw = scanner.nextLine();
        if(psw == null || psw.isEmpty()) {
            System.out.println("Invalid argument provided");
            System.exit(1);
        }

        MessageDigestWrapper messageDigestWrapper = new MessageDigestWrapper("SHA-256");
        psw = Utils.toHexString(messageDigestWrapper.computeDigest(psw.getBytes(StandardCharsets.UTF_8)));
        System.out.println(psw);
        System.out.println("ID TGS: (tgs1)");
        String id_tgs = scanner.nextLine();
        if(id_tgs == null || !id_tgs.equals("tgs1")){
            System.out.println("Invalid argument provided");
            System.exit(1);
        }

        Socket socket = null;
        try {
            socket = new Socket(authserver, AUTHENTICATION_SERVER_PORT);
            BufferedReader in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter out = new PrintWriter(socket.getOutputStream(), true);

            // STEP 1: C->AD: ID||AD_C||ID_TGS||T1
            String ad_c = socket.getLocalAddress().toString();
            String t1 = String.valueOf(System.currentTimeMillis());
            String request = id + SEPARATOR + ad_c + SEPARATOR + id_tgs + SEPARATOR + t1;
            System.out.println(request);
            out.println(request);

            // Step 2: AS->C : E_PSW(K_CT||ID_TGS||T2||D_T2||E_K_TGS(K_CT||ID||AD_C||T2||DT2))
            String encryptedResponse = in.readLine();
            if(!socket.isClosed()) {
                socket.close();
            }
            if (encryptedResponse.startsWith("Error")) {
                System.out.println("Server response: " + encryptedResponse);
                return;
            }


            // Step 3: C->TGS ID_V || E_K_TGS(K_CT||ID||AD_C||T2||DT2) || E_KCT(ID||AD_C||T3)
            String message = Utils.decryptMessage(encryptedResponse, psw);
            String[] parts = message.split(SPLIT_SEPARATOR);
            String k_ct = parts[0];
            id_tgs = parts[1];
            String t2 = parts[2];
            String d_t2 = parts[3];
            String encryptedTicket = parts[4];

            System.out.println("ID Server (s1): ");
            String id_v = scanner.nextLine();
            if(id_v == null || !id_v.equals("s1")) {
                System.out.println("Invalid argument provided");
                System.exit(1);
            }

            String t3 = String.valueOf(System.currentTimeMillis());
            String proof = id + SEPARATOR + ad_c + SEPARATOR + t3;
            String encryptedProof = Utils.encryptMessage(proof, k_ct);

            socket = new Socket(tgs, TICKET_GRANTING_SERVER_PORT);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);

            String message_step3 = id_v + SEPARATOR + encryptedTicket + SEPARATOR + encryptedProof;
            out.println(message_step3);

            String encryptedMessage_step4 = in.readLine();
            if(!socket.isClosed()) {
                socket.close();
            }
            if (encryptedMessage_step4.startsWith("Error")) {
                System.out.println("Server response: " + encryptedResponse);
                return;
            }
            String message_step4 = Utils.decryptMessage(encryptedMessage_step4, k_ct);
            System.out.println("STEP 4: " + message_step4);
            parts = message_step4.split(SPLIT_SEPARATOR);
            String k_cv = parts[0];
            id_v = parts[1];
            String t4 = parts[2];
            String e_kv = parts[3];

            //Step 5: C->V: E_KV(K_CV || ID || AD_C || T4 || DT4) || E_K_CV(ID||AD_C||T5)
            String t5 = String.valueOf(System.currentTimeMillis());
            String proof5 = id + SEPARATOR + ad_c + SEPARATOR + t5;
            String encrypted_proof5 = Utils.encryptMessage(proof5, k_cv);
            String message5 = e_kv + SEPARATOR + encrypted_proof5;

            socket = new Socket(echoserver, ECHO_SERVER_PORT);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            out = new PrintWriter(socket.getOutputStream(), true);
            out.println(message5);

            String encrypted_message6 = in.readLine();
            if (encrypted_message6.startsWith("ERROR")) {
                System.out.println("Server response: " + encryptedResponse);
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
                if(!socket.isClosed()) {
                    socket.close();
                }
            }

            // STEP 7: C->V: E_K_CV(ID||AD_C||TIMESTAMP||PAYLOAD)||H(ID||AD_C||TIMESTAMP||PAYLOAD)
            System.out.println("Contenuto da scrivere sul server: ");
            String payload = scanner.nextLine();
            do {
                String timestamp = String.valueOf(System.currentTimeMillis());
                request = id + SEPARATOR + ad_c + SEPARATOR + timestamp + SEPARATOR + payload;
                String encryptedRequest = Utils.encryptMessage(request, k_cv);
                String requestDigest = Utils.toHexString(messageDigestWrapper.computeDigest(Utils.toByteArray(request)));
                message = encryptedRequest + SEPARATOR + requestDigest;
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

            if(!socket.isClosed()) {
                socket.close();
            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
        }
    }
}
