import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.interfaces.DHPublicKey;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.ServerSocket;
import java.net.Socket;

public class Server implements Runnable {

    // Networking
    private int port;
    private ServerSocket serverSocket;
    private Socket clientSocket;

    // Server state
    private boolean isSetup = false;
    private boolean isVerified = false;
    private boolean isFinished = false;
    private boolean hasGenSession;
    private boolean hasExchanged = false;

    // Server details
    private String serverID;
    private String sessionID;

    // RSA values
    private BigInteger RSAp;
    private BigInteger RSAq;
    private BigInteger RSAn;
    private BigInteger RSApubKey = new BigInteger("65537");

    // DHE values
    private static BigInteger DHp = new BigInteger(
            "178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
    private static BigInteger DHg = new BigInteger(
            "174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");
    private BigInteger DHa;
    private BigInteger DHpubKey;
    private BigInteger DHclientKey;
    private BigInteger sessionKey;

    Server(int port) {
        this.port = port;
        this.serverID = "r1241234jdasdjkfasdf";
        this.sessionID = "sdfasdfasdjfkk4325345";
        try {
            serverSocket = new ServerSocket(port);

        } catch (Exception e) {
            System.err.println(e);
        }

    }

    @Override
    public void run() {

        try {

            // Network connections
            Socket socket = serverSocket.accept();
            BufferedReader input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintWriter output = new PrintWriter(socket.getOutputStream(), true);

            while (!isSetup) {

                if (input.ready()) {
                    String message = input.readLine();
                    if (message.contains("Hello")) {
                        System.out.println("Client to server: " + message);

                        RSAp = SSL.primeGen();
                        RSAq = SSL.primeGen();
                        RSAn = SSL.modulusGen(RSAp, RSAq);
                        output.println("e=" + RSApubKey + " n=" + RSAn);
                        output.flush();
                        isSetup = true;
                    }

                }

            }

            while (!isVerified) {

                if (input.ready()) {
                    String message = input.readLine();

                    if (message.contains("IDc")) {
                        System.out.println("Client to server: " + message);
                        output.println("IDs=" + serverID + " SID=" + sessionID);
                        output.flush();
                        isVerified = true;
                    }

                }

            }

            while (!hasExchanged) {

                if (input.ready()) {
                    String message = input.readLine();

                    if (message.contains("ID received")) {
                        System.out.println("Client to server: " + message);
                        DHa = SSL.DHrandom(DHp);
                        DHpubKey = SSL.DHpubKeyGen(DHa, DHg, DHp);

                        // supposed to RSA encrypt I think
                        output.println("DHg=" + DHg + " DHp=" + DHp + " DHpubkey=" + DHpubKey);
                        output.flush();
                        hasExchanged = true;
                    }

                }

            }

            while (!hasGenSession) {
                if (input.ready()) {
                    String message = input.readLine();

                    if (message.contains("DHpub")) {

                        DHclientKey = SSL.findDHpubkey(message);
                        sessionKey = SSL.calculateSessionKey(DHclientKey, DHa, DHp);
                    }
                    hasGenSession = true;
                }

            }

            while (!isFinished) {
                if (input.ready()) {
                    String message = input.readLine();
                    message = SSL.AESdecrypt(message, sessionKey);

                    if (message.contains("exit")) {
                        System.out.println("Server exiting...");
                        output.println(SSL.AESencrypt(sessionKey, "exit"));
                        output.flush();
                        Thread.sleep(1000);
                        isFinished = true;
                    } else {
                        System.out.println("Client to server: " + message);
                    }

                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

}
