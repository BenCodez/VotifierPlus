package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import com.google.gson.Gson;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.VoteReceiver;

/**
 * Test class for VoteReceiver that supports both V2 (JSON) and V1 (RSA encrypted) vote processing.
 */
public class VoteReceiverTest {

    private static final int TEST_PORT = 12345;
    private static final String TEST_HOST = "localhost";
    private static final Gson gson = new Gson();

    // Concrete subclass for testing
    private static class TestVoteReceiver extends VoteReceiver {

        // Captured vote for verification
        public Vote capturedVote;
        // Reuse a single key pair for both encryption and decryption
        private final KeyPair keyPair;

        public TestVoteReceiver(String host, int port) throws Exception {
            super(host, port);
            this.keyPair = generateDummyKeyPair();
        }

        @Override
        public boolean isUseTokens() {
            // For V2 processing, tokens are used.
            // For V1, this flag is not used since vote encryption is applied.
            return true;
        }

        @Override
        public void logWarning(String warn) {
            // No-op for testing.
        }

        @Override
        public void logSevere(String msg) {
            // No-op for testing.
        }

        @Override
        public void log(String msg) {
            // No-op for testing.
        }

        @Override
        public void debug(String msg) {
            // No-op for testing.
        }

        @Override
        public String getVersion() {
            return "test";
        }

        @Override
        public Set<String> getServers() {
            // Return an empty set so that no vote forwarding occurs.
            return Collections.emptySet();
        }

        @Override
        public KeyPair getKeyPair() {
            // Return the same key pair every time.
            return keyPair;
        }

        @Override
        public Map<String, Key> getTokens() {
            // Use a dummy HMAC key for V2 vote processing.
            Map<String, Key> tokens = new HashMap<>();
            SecretKeySpec keySpec = new SecretKeySpec("secretsecretsecret".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
            tokens.put("TestService", keySpec);
            tokens.put("default", keySpec);
            return tokens;
        }

        @Override
        public ForwardServer getServerData(String s) {
            return null; // No forwarding in tests.
        }

        @Override
        public void callEvent(Vote e) {
            // Capture the vote so it can be verified by the test.
            this.capturedVote = e;
        }

        @Override
        public void debug(Exception e) {
            // No-op for testing.
        }
    }

    private TestVoteReceiver voteReceiver;

    @BeforeEach
    public void setUp() throws Exception {
        // Start the VoteReceiver on the test host and port.
        voteReceiver = new TestVoteReceiver(TEST_HOST, TEST_PORT);
        voteReceiver.setDaemon(true);
        voteReceiver.start();
        // Allow a brief pause for the server socket to bind.
        Thread.sleep(200);
    }

    @AfterEach
    public void tearDown() throws Exception {
        // Shutdown the VoteReceiver after tests.
        voteReceiver.shutdown();
        voteReceiver.join(1000);
    }

    @Test
    public void testValidV2VoteProcessing() throws Exception {
        // Connect to the VoteReceiver as a client.
        Socket clientSocket = new Socket();
        clientSocket.connect(new InetSocketAddress(TEST_HOST, TEST_PORT), 1000);
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8));

        // --- Read Handshake ---
        String handshake = reader.readLine();
        assertNotNull(handshake, "Handshake should not be null");
        assertTrue(handshake.startsWith("VOTIFIER 2 "), "Unexpected handshake: " + handshake);

        // --- Build V2 Vote Payload ---
        String innerPayload = "{\"serviceName\":\"TestService\",\"username\":\"TestUser\",\"address\":\"127.0.0.1\",\"timestamp\":\"2025-02-16T00:00:00Z\"}";
        SecretKeySpec keySpec = new SecretKeySpec("secretsecretsecret".getBytes(StandardCharsets.UTF_8), "HmacSHA256");
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(keySpec);
        byte[] hmacBytes = mac.doFinal(innerPayload.getBytes(StandardCharsets.UTF_8));
        String hmacBase64 = Base64.getEncoder().encodeToString(hmacBytes);
        String voteJson = "{\"payload\":" + gson.toJson(innerPayload) + ",\"signature\":\"" + hmacBase64 + "\"}";

        // --- Send Vote Payload ---
        writer.write(voteJson);
        writer.flush();
        clientSocket.shutdownOutput();

        // --- Read OK Response ---
        String okResponse = reader.readLine();
        assertNotNull(okResponse, "OK response should not be null");
        assertTrue(okResponse.contains("\"status\":\"ok\""), "Unexpected OK response: " + okResponse);

        // Allow time for VoteReceiver to process the vote.
        Thread.sleep(200);
        assertNotNull(voteReceiver.capturedVote, "Vote event should have been triggered");
        assertEquals("TestService", voteReceiver.capturedVote.getServiceName(), "Service name mismatch");
        assertEquals("TestUser", voteReceiver.capturedVote.getUsername(), "Username mismatch");
        assertEquals("127.0.0.1", voteReceiver.capturedVote.getAddress(), "Address mismatch");
        assertEquals("2025-02-16T00:00:00Z", voteReceiver.capturedVote.getTimeStamp(), "Timestamp mismatch");

        clientSocket.close();
    }

    @Test
    public void testValidV1VoteProcessing() throws Exception {
        // Connect to the VoteReceiver as a client.
        Socket clientSocket = new Socket();
        clientSocket.connect(new InetSocketAddress(TEST_HOST, TEST_PORT), 1000);
        BufferedReader reader = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));

        // --- Read Handshake ---
        String handshake = reader.readLine();
        assertNotNull(handshake, "Handshake should not be null");
        assertTrue(handshake.startsWith("VOTIFIER 2 "), "Unexpected handshake: " + handshake);

        // --- Build V1 Vote Payload ---
        StringBuilder payloadBuilder = new StringBuilder();
        payloadBuilder.append("VOTE\n");           // opcode
        payloadBuilder.append("TestService\n");      // serviceName
        payloadBuilder.append("TestUser\n");         // username
        payloadBuilder.append("127.0.0.1\n");          // address
        payloadBuilder.append("TestV1\n");           // timestamp
        String plaintext = payloadBuilder.toString();

        // Encrypt the plaintext using the RSA public key (from our stored key pair).
        byte[] encryptedBlock = voteReceiver.encrypt(plaintext.getBytes(StandardCharsets.UTF_8),
                voteReceiver.getKeyPair().getPublic());
        assertEquals(256, encryptedBlock.length, "Encrypted block should be 256 bytes");

        // --- Send the Encrypted V1 Block ---
        clientSocket.getOutputStream().write(encryptedBlock);
        clientSocket.getOutputStream().flush();
        clientSocket.shutdownOutput();

        // --- Read OK Response ---
        String okResponse = reader.readLine();
        assertNotNull(okResponse, "OK response should not be null");
        assertTrue(okResponse.contains("\"status\":\"ok\""), "Unexpected OK response: " + okResponse);

        // Allow time for the VoteReceiver to process the vote.
        Thread.sleep(200);
        assertNotNull(voteReceiver.capturedVote, "Vote event should have been triggered");
        assertEquals("TestService", voteReceiver.capturedVote.getServiceName(), "Service name mismatch");
        assertEquals("TestUser", voteReceiver.capturedVote.getUsername(), "Username mismatch");
        assertEquals("127.0.0.1", voteReceiver.capturedVote.getAddress(), "Address mismatch");
        assertEquals("TestV1", voteReceiver.capturedVote.getTimeStamp(), "Timestamp mismatch");

        clientSocket.close();
    }

    /**
     * Generates a dummy RSA key pair (2048-bit) for testing purposes.
     */
    private static KeyPair generateDummyKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048); // Use a 2048-bit key so that encryption produces a 256-byte block.
        return keyGen.generateKeyPair();
    }
}
