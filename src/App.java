public class App {

    private static int PORT = 4600;
    private static Server server = new Server(PORT);
    private static Thread serverThread = new Thread(server);

    private static Client client = new Client(PORT);
    private static Thread clientThread = new Thread(client);

    public static void main(String[] args) {

        serverThread.start();
        clientThread.start();

    }

}
