package encryption_Assignment1;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Scanner;

public class SenderClient {

    private static final String SERVER_HOST = "127.0.0.1";
    private static final int SERVER_PORT = 6000;

    private final String username;    // e.g., "Alice"
    private final String peer;        // e.g., "Bob"

    private KeyPair rsaKeyPair;
    private PublicKey peerRsaPublicKey;
    private SecretKey aesSessionKey;
    private PrintWriter out;
    private BufferedReader in;

    private final File logFile = new File("messages.json");

    public SenderClient(String username, String peer) {
        this.username = username;
        this.peer = peer;
    }

    public void start() throws Exception {
        generateRsaKeyPair();
        try (Socket socket = new Socket(SERVER_HOST, SERVER_PORT)) {
            System.out.println("Connected to Server.");
            in  = new BufferedReader(new InputStreamReader(socket.getInputStream(), "UTF-8"));
            out = new PrintWriter(new OutputStreamWriter(socket.getOutputStream(), "UTF-8"), true);

            register();
            fetchPeerPublicKey();
            establishSession();

            System.out.println("Session established with " + peer + ". Type messages and press ENTER to send. Ctrl+C to exit.");

            Scanner sc = new Scanner(System.in);
            while (true) {
                String msg = sc.nextLine();
                sendEncryptedMessage(msg);
                appendLogSent(msg); // sender knows plaintext and will log what they sent
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

    private void fetchPeerPublicKey() throws Exception {
        out.println("GET_PUBKEY|" + peer);
        String resp = in.readLine();
        if (resp == null || !resp.startsWith("PUBKEY|")) {
            throw new IOException("Failed to fetch pubkey for " + peer + ": " + resp);
        }
        String[] parts = resp.split("\\|", -1);
        String b64 = parts[2];
        byte[] der = Base64.getDecoder().decode(b64);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        peerRsaPublicKey = KeyFactory.getInstance("RSA").generatePublic(spec);
        System.out.println("Got " + peer + "'s public key.");
    }

    private void establishSession() throws Exception {
        // Generate AES session key (AES-128; adjust to 256 if needed)
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(128);
        aesSessionKey = kg.generateKey();

        // Encrypt AES key with peer's RSA public key
        Cipher rsa = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, peerRsaPublicKey);
        byte[] enc = rsa.doFinal(aesSessionKey.getEncoded());
        String encB64 = Base64.getEncoder().encodeToString(enc);

        out.println("START_SESSION|" + username + "|" + peer + "|" + encB64);
        System.out.println("Generated AES session key and sent to " + peer + ".");
    }

    private void sendEncryptedMessage(String plaintext) throws Exception {
        // AES/GCM encryption
        byte[] iv = new byte[12];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(iv);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(128, iv);
        aes.init(Cipher.ENCRYPT_MODE, aesSessionKey, spec);
        byte[] ct = aes.doFinal(plaintext.getBytes("UTF-8"));

        String ivB64 = Base64.getEncoder().encodeToString(iv);
        String ctB64 = Base64.getEncoder().encodeToString(ct);

        out.println("MSG|" + username + "|" + peer + "|" + ivB64 + "|" + ctB64);
        System.out.println("Encrypted Message: " + ctB64);
        System.out.println("Message sent successfully.");
    }

    private synchronized void appendLogSent(String plaintext) {
        try (FileWriter fw = new FileWriter(logFile, true);
             BufferedWriter bw = new BufferedWriter(fw);
             PrintWriter pw = new PrintWriter(bw)) {
            // JSON lines (one object per line)
            String json = String.format(
                "{\"direction\":\"sent\",\"to\":\"%s\",\"decrypted\":\"%s\"}",
                escape(peer), escape(plaintext)
            );
            pw.println(json);
        } catch (IOException ignored) {}
    }

    private static String escape(String s) {
        return s.replace("\\", "\\\\").replace("\"", "\\\"");
    }

    public static void main(String[] args) throws Exception {
        String me = (args.length >= 1) ? args[0] : "Alice";
        String to = (args.length >= 2) ? args[1] : "Bob";
        new SenderClient(me, to).start();
    }
}