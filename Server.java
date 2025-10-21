package assignment1_Encryption;

import java.io.*;
import java.net.*;
import java.util.concurrent.ConcurrentHashMap;

public class Server {
    private static final int PORT = 5000;
    private static final ConcurrentHashMap<String, ObjectOutputStream> clients = new ConcurrentHashMap<>();

    public static void main(String[] args) {
        try (ServerSocket serverSocket = new ServerSocket(PORT)) {
            System.out.println("Server started on port " + PORT);
            while (true) {
                Socket socket = serverSocket.accept();
                new ClientHandler(socket).start();
            }
        } catch (IOException e) {
            System.out.println("Server error: " + e.getMessage());
        }
    }

    static class ClientHandler extends Thread {
        private final Socket socket;
        private String clientName;

        ClientHandler(Socket socket) {
            this.socket = socket;
        }

        @Override public void run() {
            try (
                ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
                ObjectInputStream in  = new ObjectInputStream(socket.getInputStream())
            ) {
                clientName = (String) in.readObject();
                clients.put(clientName, out);
                System.out.println(clientName + " connected.");

                while (true) {
                    String receiver    = (String) in.readObject();
                    String encryptedMsg = (String) in.readObject();

                    System.out.println("Encrypted message received from " + clientName + ": " + encryptedMsg);

                    ObjectOutputStream recvOut = clients.get(receiver);
                    if (recvOut != null) {
                        recvOut.writeObject(clientName);
                        recvOut.writeObject(encryptedMsg);
                        recvOut.flush();
                    } else {
                        System.out.println(receiver + " not connected.");
                    }
                }
            } catch (Exception e) {
                System.out.println("Connection closed for " + clientName);
                try { socket.close(); } catch (IOException ignored) {}
            } finally {
                if (clientName != null) clients.remove(clientName);
            }
        }
    }
}