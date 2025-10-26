package encryption_Assignment1;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class ReceiverClient {

    private static final String SERVER_HOST = "127.0.0.1";
    private static final int SERVER_PORT = 6000;

    private final String username; // e.g., "Bob"
    private KeyPair rsaKeyPair;
    private SecretKey aesSessionKey;
    private PrintWriter out;
    private BufferedReader in;

    private final File logFile = new File("messages.json");

    public ReceiverClient(String username) {
        this.username = username;
    }

    public void start() throws Exception {
        generateRsaKeyPair();
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println("Connected to Server.");
            in  = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            register();

            // Background reader for server-pushed messages
            new Thread(this::readLoop).start();

            // Keep process alive
            while (true) {
                Thread.sleep(1000);
            }
        }
    }

    private void generateRsaKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        rsaKeyPair = kpg.generateKeyPair();
    }

    private void register() throws IOException {
        String pubB64 = Base64.getEncoder().encodeToString(rsaKeyPair.getPublic().getEncoded());
        out.println("REGISTER|" + username + "|" + pubB64);
        String resp = in.readLine();
        if (resp == null || !resp.startsWith("REGISTERED|")) {
            throw new IOException("Registration failed: " + resp);
        }
        System.out.println("Registered as " + username + ".");
    }

    private void readLoop() {
        String line;
        try {
            while ((line = in.readLine()) != null) {
                String[] parts = line.split("\\|", -1);
                String cmd = parts[0];
                switch (cmd) {
                    case "START_SESSION": {
                        // START_SESSION|<from>|<to>|<B64_ENC_AES_KEY>
                        String from = parts[1];
                        String encB64 = parts[3];
                        try {
                            byte[] enc = Base64.getDecoder().decode(encB64);
                            Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                            rsa.init(Cipher.DECRYPT_MODE, rsaKeyPair.getPrivate());
                            byte[] raw = rsa.doFinal(enc);
                            aesSessionKey = new SecretKeySpec(raw, "AES");
                            System.out.println("Session key received from " + from + " and decrypted.");
                        } catch (Exception e) {
                            System.out.println("Failed to decrypt session key: " + e.getMessage());
                        }
                        break;
                    }
                    case "MSG": {
                        // MSG|<from>|<to>|<B64_IV>|<B64_CIPHERTEXT>
                        String from = parts[1];
                        String ivB64 = parts[3];
                        String ctB64 = parts[4];

                        // Show encrypted first
                        System.out.println("Received encrypted message: " + ctB64);

                        // Then decrypt & print plaintext
                        String plaintext = "(no session key yet)";
                        if (aesSessionKey != null) {
                            try {
                                byte[] iv = Base64.getDecoder().decode(ivB64);
                                byte[] ct = Base64.getDecoder().decode(ctB64);
                                Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
                                GCMParameterSpec spec = new GCMParameterSpec(128, iv);
                                aes.init(Cipher.DECRYPT_MODE, aesSessionKey, spec);
                                byte[] pt = aes.doFinal(ct);
                                plaintext = new String(pt, "UTF-8");
                            } catch (Exception e) {
                                plaintext = "(decryption failed: " + e.getMessage() + ")";
                            }
                        }
                        System.out.println("Decrypted message: " + plaintext);

                        appendLogReceived(from, ctB64, plaintext);
                        break;
                    }
                    case "PUBKEY":
                    case "REGISTERED":
                    case "ERROR":
                        // Receiver doesn't need these normally; ignore or print if you want.
                        break;
                    default:
                        // Unknown or not needed here
                }
            }
        } catch (IOException ignored) { }
    }

    private synchronized void appendLogReceived(String from, String ciphertextB64, String plaintext) {
        try (FileWriter fw = new FileWriter(logFile, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter pw = new PrintWriter(bw)) {
            // JSON lines (one object per line)
            String json = String.format(
                "{\"direction\":\"received\",\"from\":\"%s\",\"encrypted\":\"%s\",\"decrypted\":\"%s\"}",
                escape(from), escape(ciphertextB64), escape(plaintext)
            );
            pw.println(json);
        } catch (IOException ignored) {}
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static void main(String[] args) throws Exception {
        String me = (args.length >= 1) ? args[0] : "Bob";
        new ReceiverClient(me).start();
    }
}