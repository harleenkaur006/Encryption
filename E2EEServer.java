package encryption_Assignment1;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class E2EEServer {

    private static class ClientInfo {
        String username;
        PrintWriter out;
        String base64PubKey; // X.509 encoded RSA public key (Base64)

        ClientInfo(String username, PrintWriter out) {
            this.username = username;
            this.out = out;
        }
    }

    private final int port;
    private final Map<String, ClientInfo> clients = new ConcurrentHashMap<>();

    public E2EEServer(int port) {
        this.port = port;
    }

    public void start() throws IOException {
        try (ServerSocket serverSocket = new ServerSocket(port)) {
            System.out.println("Server started on port " + port + ".");
            while (true) {
                Socket socket = serverSocket.accept();
                new Thread(new ClientHandler(socket)).start();
            }
        }
    }

    private class ClientHandler implements Runnable {
        private final Socket socket;
        private BufferedReader in;
        private PrintWriter out;
        private String username = null;

        ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override
        public void run() {
            try (
                Socket s = socket;
            ) {
                in = new BufferedReader(new InputStreamReader(s.getInputStream(), "UTF-8"));
                out = new PrintWriter(new OutputStreamWriter(s.getOutputStream(), "UTF-8"), true);

                String line;
                while ((line = in.readLine()) != null) {
                    // Protocol lines: COMMAND|field1|field2|... (Base64 for binary)
                    String[] parts = line.split("\\|", -1);
                    String cmd = parts[0];

                    switch (cmd) {
                        case "REGISTER": {
                            // REGISTER|<username>|<Base64PubKey>
                            if (parts.length < 3) break;
                            username = parts[1];
                            String b64pk = parts[2];
                            ClientInfo info = new ClientInfo(username, out);
                            info.base64PubKey = b64pk;
                            clients.put(username, info);
                            System.out.println("REGISTER from " + username);
                            out.println("REGISTERED|" + username);
                            break;
                        }
                        case "GET_PUBKEY": {
                            // GET_PUBKEY|<target>
                            if (parts.length < 2) break;
                            String target = parts[1];
                            ClientInfo ti = clients.get(target);
                            if (ti != null && ti.base64PubKey != null) {
                                out.println("PUBKEY|" + target + "|" + ti.base64PubKey);
                            } else {
                                out.println("ERROR|NO_PUBKEY|" + target);
                            }
                            break;
                        }
                        case "START_SESSION": {
                            // START_SESSION|<from>|<to>|<B64_ENC_AES_KEY>
                            if (parts.length < 4) break;
                            String from = parts[1];
                            String to = parts[2];
                            String encKey = parts[3];
                            ClientInfo ti = clients.get(to);
                            if (ti != null) {
                                System.out.println("START_SESSION from " + from + " -> " + to);
                                ti.out.println("START_SESSION|" + from + "|" + to + "|" + encKey);
                            } else {
                                out.println("ERROR|NO_SUCH_USER|" + to);
                            }
                            break;
                        }
                        case "MSG": {
                            // MSG|<from>|<to>|<B64_IV>|<B64_CIPHERTEXT>
                            if (parts.length < 5) break;
                            String from = parts[1];
                            String to = parts[2];
                            String iv = parts[3];
                            String ct = parts[4];

                            // Log ciphertext at the server (server can't decrypt)
                            System.out.println("CIPHERTEXT on server from " + from + " -> " + to + ": " + ct);

                            ClientInfo ti = clients.get(to);
                            if (ti != null) {
                                ti.out.println("MSG|" + from + "|" + to + "|" + iv + "|" + ct);
                            } else {
                                out.println("ERROR|NO_SUCH_USER|" + to);
                            }
                            break;
                        }
                        default:
                            out.println("ERROR|UNKNOWN_CMD|" + cmd);
                    }
                }
            } catch (IOException e) {
                // Client disconnected or IO issue
            } finally {
                if (username != null) {
                    clients.remove(username);
                    System.out.println("Disconnected: " + username);
                }
            }
        }
    }

    public static void main(String[] args) throws Exception {
        int port = 6000;
        if (args.length >= 1) {
            port = Integer.parseInt(args[0]);
        }
        new E2EEServer(port).start();
    }
}