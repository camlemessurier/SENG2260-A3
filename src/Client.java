import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Scanner;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class Client implements Runnable {

    // Network connections
    private int port;
    private Socket socket;
    private BufferedReader input;
    private PrintWriter output;

    // Client state
    private boolean isSetup = false;
    private boolean isVerified = false;
    private boolean hasExchanged = false;
    private Boolean isFinished = false;

    // Client details
    private String clientID;

    // DH values
    private BigInteger DHserverKey;
    private BigInteger DHpubKey;
    private BigInteger DHb;
    private BigInteger DHg;
    private BigInteger DHp;
    private BigInteger sessionKey;

    // RSA
    private BigInteger e;
    private BigInteger n;

    Client(int port) {
        this.port = port;
        this.clientID = "213848293452039485273849"; // TODO UUID
    }

    @Override
    public void run() {

        try {

            socket = new Socket("localhost", port);
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

            System.out.println("Setup Phase");
            System.out.println("_______________\n");
            output.println("Hello: SSL_DHE_RSA_WITH_AES_256_CBC_SHA");
            output.flush();

            while (!isSetup) {

                if (input.ready()) {
                    String message = input.readLine();
                    if (message.contains("e=") && message.contains("n=")) {
                        System.out.println("Server to client: " + message);
                        e = SSL.findE(message);
                        n = SSL.findN(message);
                        isSetup = true;
                    }

                }

            }

            System.out.println("\n\n\nHandshake Phase");
            System.out.println("_______________\n");
            output.println("IDc=" + clientID);
            output.flush();

            while (!isVerified) {

                if (input.ready()) {
                    String message = input.readLine();
                    if (message.contains("IDs=") && message.contains("SID=")) {
                        System.out.println("Server to client: " + message);
                        output.println("ID received");
                        isVerified = true;
                    }

                }
            }

            while (!hasExchanged) {

                if (input.ready()) {
                    String message = input.readLine();
                    if (message.contains("DHg=")) {
                        System.out.println("Server to client: " + message);
                        DHg = SSL.findDHg(message);
                        DHp = SSL.findDHp(message);
                        DHb = SSL.DHrandom(DHp);
                        DHpubKey = SSL.DHpubKeyGen(DHb, DHg, DHp);
                        output.println("DHpubkey=" + DHpubKey);
                        DHserverKey = SSL.findDHpubkey(message);
                        sessionKey = SSL.calculateSessionKey(DHserverKey, DHb, DHp);
                        hasExchanged = true;
                    }

                }
            }

            System.out.println("\n\n\nData Exchange");
            System.out.println("_______________\n");

            Scanner scanner = new Scanner(System.in);

            while (!isFinished) {

                if (input.ready()) {
                    String serverMessage = input.readLine();
                    serverMessage = SSL.AESdecrypt(serverMessage, sessionKey);
                    if (serverMessage.contains("exit")) {
                        System.out.println("Client exiting...");
                        isFinished = true;
                        break;
                    } else {
                        System.out.println("Server to Client: " + serverMessage);
                    }

                }

                System.out.println("Enter message");

                String message = scanner.nextLine();
                message = SSL.AESencrypt(sessionKey, message);
                output.println(message);

                output.flush();

                Thread.sleep(100);

            }
            scanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
