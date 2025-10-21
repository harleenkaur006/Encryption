package assignment1_Encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;

public class Client {
    private static final String SERVER = "localhost";
    private static final int PORT = 5000;
    private static final String JSON_FILE = "messages.json";

    // Keys are generated to mirror the assignment flow (registration/keypair),
    // but for simplicity of the demo we use a fixed AES session key to keep output the same.
    private static PrivateKey privateKey;
    private static PublicKey  publicKey;

    public static void main(String[] args) throws Exception {
        Scanner sc = new Scanner(System.in);

        System.out.print("Enter your name (Alice/Bob): ");
        String name = sc.nextLine().trim();

        // Generate RSA keypair (registration step)
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        privateKey = kp.getPrivate();
        publicKey  = kp.getPublic();
        // (Public key “registration” with a directory/server is skipped in this minimal demo)

        System.out.print("Enter receiver name: ");
        String receiver = sc.nextLine().trim();

        // Connect to server
        Socket socket = new Socket(SERVER, PORT);
        ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());
        ObjectInputStream  in  = new ObjectInputStream(socket.getInputStream());

        // Register this client's name with server
        out.writeObject(name);
        out.flush();

        // Thread to receive messages
        Thread recvThread = new Thread(() -> {
            try {
                while (true) {
                    String sender   = (String) in.readObject();
                    String encMsg   = (String) in.readObject();

                    System.out.println("\n[Encrypted from " + sender + "]: " + encMsg);

                    // Demo session key (16 bytes -> AES-128)
                    SecretKey sessionKey = new SecretKeySpec("1234567890123456".getBytes(StandardCharsets.UTF_8), "AES");
                    String decrypted = decryptAES(encMsg, sessionKey);

                    System.out.println("[Decrypted]: " + decrypted);

                    // Log to messages.json (append as array)
                    appendJsonLog(sender, decrypted, encMsg);
                    System.out.print("Enter message: "); // keep prompt handy
                }
            } catch (Exception e) {
                System.out.println("Receiver disconnected.");
            }
        });
        recvThread.setDaemon(true);
        recvThread.start();

        // Send loop
        while (true) {
            System.out.print("Enter message: ");
            String msg = sc.nextLine();

            SecretKey sessionKey = new SecretKeySpec("1234567890123456".getBytes(StandardCharsets.UTF_8), "AES");
            String encrypted = encryptAES(msg, sessionKey);

            out.writeObject(receiver);
            out.writeObject(encrypted);
            out.flush();

            appendJsonLog(receiver, msg, encrypted);
        }
    }

    // --- AES helpers (standard JDK) ---
    private static String encryptAES(String msg, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding"); // simple for demo
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] ct = cipher.doFinal(msg.getBytes(StandardCharsets.UTF_8));
        return Base64.getEncoder().encodeToString(ct);
    }

    private static String decryptAES(String b64cipher, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] pt = cipher.doFinal(Base64.getDecoder().decode(b64cipher));
        return new String(pt, StandardCharsets.UTF_8);
    }

    // --- Minimal JSON array appender (no external libraries) ---
    private static void appendJsonLog(String partner, String plaintext, String ciphertext) {
        try {
            String obj = "{"
                    + "\"partner\":\""   + escapeJson(partner)   + "\","
                    + "\"plaintext\":\"" + escapeJson(plaintext) + "\","
                    + "\"ciphertext\":\""+ escapeJson(ciphertext)+ "\""
                    + "}";

            File f = new File(JSON_FILE);
            if (!f.exists() || f.length() == 0) {
                // create new array with the first object
                try (FileWriter fw = new FileWriter(f, false)) {
                    fw.write("[\n  " + obj + "\n]\n");
                }
                return;
            }

            // read current content
            String content = new String(Files.readAllBytes(Paths.get(JSON_FILE)), StandardCharsets.UTF_8).trim();

            // if somehow file isn't a JSON array, recreate
            if (!content.endsWith("]")) {
                try (FileWriter fw = new FileWriter(f, false)) {
                    fw.write("[\n  " + obj + "\n]\n");
                }
                return;
            }

            // insert before the last ']'
            String withoutClosing = content.substring(0, content.lastIndexOf(']')).trim();
            boolean hasAny = withoutClosing.contains("{");

            StringBuilder sb = new StringBuilder();
            sb.append(hasAny ? withoutClosing + ",\n  " + obj + "\n]" : "[\n  " + obj + "\n]");
            try (FileWriter fw = new FileWriter(f, false)) {
                fw.write(sb.toString());
            }
        } catch (Exception e) {
            System.out.println("Failed to write messages.json: " + e.getMessage());
        }
    }

    private static String escapeJson(String s) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '\\': out.append("\\\\"); break;
                case '\"': out.append("\\\""); break;
                case '\b': out.append("\\b");  break;
                case '\f': out.append("\\f");  break;
                case '\n': out.append("\\n");  break;
                case '\r': out.append("\\r");  break;
                case '\t': out.append("\\t");  break;
                default:
                    if (c < 0x20) {
                        out.append(String.format("\\u%04x", (int)c));
                    } else {
                        out.append(c);
                    }
            }
        }
        return out.toString();
    }
}