/*
 * Copyright (C) 2012 Vex Software LLC
 * This file is part of Votifier.
 * 
 * Votifier is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 * 
 * Votifier is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with Votifier.  If not, see <http://www.gnu.org/licenses/>.
 * 
 * @author Blake Beaupain
 * @author Kramer Campbell
 * 
 * Modified to support handling of extra proxy protocol data (e.g. from HAProxy).
 * 
 * Modified by: BenCodez
 * 
 */
package com.vexsoftware.votifier.net;

import java.io.BufferedWriter;
import java.io.ByteArrayOutputStream;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Set;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;

import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.crypto.RSA;
import com.vexsoftware.votifier.model.Vote;

public abstract class VoteReceiver extends Thread {

    /** The host to listen on. */
    private final String host;
    /** The port to listen on. */
    private final int port;
    /** The server socket. */
    private ServerSocket server;
    /** The running flag. */
    private boolean running = true;

    // The fixed signature for PROXY protocol v2 (12 bytes).
    private static final byte[] PROXY_V2_SIGNATURE = new byte[] {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };

    /**
     * Instantiates a new vote receiver.
     *
     * @param host The host to listen on
     * @param port The port to listen on
     * @throws Exception exception
     */
    public VoteReceiver(String host, int port) throws Exception {
        super("Votifier I/O");
        this.host = host;
        this.port = port;
        setPriority(Thread.MIN_PRIORITY);
        initialize();
    }

    private void initialize() throws Exception {
        try {
            server = new ServerSocket();
            server.bind(new InetSocketAddress(host, port));
            debug(server.getInetAddress().getHostAddress() + ":" + server.getLocalPort());
        } catch (Exception ex) {
            logSevere("Error initializing vote receiver. Please verify that the configured");
            logSevere("IP address and port are not already in use. This is a common problem");
            logSevere("with hosting services and, if so, you should check with your hosting provider.");
            ex.printStackTrace();
            throw new Exception(ex);
        }
    }

    public abstract void logWarning(String warn);
    public abstract void logSevere(String msg);
    public abstract void log(String msg);
    public abstract void debug(String debug);
    public abstract String getVersion();

    /**
     * Shuts the vote receiver down cleanly.
     */
    public void shutdown() {
        running = false;
        if (server == null)
            return;
        try {
            server.close();
        } catch (Exception ex) {
            logWarning("Unable to shut down vote receiver cleanly.");
        }
    }

    public abstract Set<String> getServers();
    public abstract KeyPair getKeyPair();

    @Override
    public void run() {
        // Main loop.
        while (running) {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000); // Don't hang on slow connections.

                // Wrap input in a PushbackInputStream (512-byte buffer)
                PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 512);
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

                // Read up to 16 bytes to detect any extra protocol wrappers.
                byte[] headerPeek = new byte[16];
                int bytesPeeked = in.read(headerPeek);
                if (bytesPeeked > 0) {
                    // Check for PROXY protocol v2 signature.
                    if (bytesPeeked >= 12 && isProxyV2(headerPeek)) {
                        // Read remaining 4 bytes (version/command and length fields) are already in headerPeek.
                        // The last two bytes (offsets 14 and 15) indicate the length of the remaining header.
                        int addrLength = ((headerPeek[14] & 0xFF) << 8) | (headerPeek[15] & 0xFF);
                        // Calculate total v2 header length (16 + addrLength)
                        int totalHeaderLength = 16 + addrLength;
                        byte[] remaining = new byte[addrLength];
                        int r = in.read(remaining);
                        if (r != addrLength) {
                            throw new Exception("Incomplete PROXY protocol v2 header");
                        }
                        debug("Discarded PROXY protocol v2 header (total " + totalHeaderLength + " bytes)");
                    } else {
                        String headerString = new String(headerPeek, 0, bytesPeeked, "ASCII");
                        if (headerString.startsWith("PROXY")) {
                            // PROXY protocol v1: push back and then handle as before.
                            in.unread(headerPeek, 0, bytesPeeked);
                            byte[] probe = new byte[5];
                            int read = in.read(probe);
                            if (read == 5) {
                                String probeStr = new String(probe, "ASCII");
                                if (probeStr.equals("PROXY")) {
                                    ByteArrayOutputStream headerBytes = new ByteArrayOutputStream();
                                    headerBytes.write(probe, 0, 5);
                                    int b;
                                    while ((b = in.read()) != -1) {
                                        headerBytes.write(b);
                                        if (b == '\n') {
                                            break;
                                        }
                                    }
                                    String proxyHeader = headerBytes.toString("ASCII").trim();
                                    debug("Discarded PROXY (v1) header: " + proxyHeader);
                                }
                            }
                        } else if (headerString.startsWith("CONNECT")) {
                            // HTTP CONNECT tunneling.
                            in.unread(headerPeek, 0, bytesPeeked);
                            String connectLine = readLine(in);
                            debug("Received CONNECT request: " + connectLine);
                            // Read and discard all headers.
                            String line;
                            while (!(line = readLine(in)).isEmpty()) {
                                debug("Discarding header: " + line);
                            }
                            // Send HTTP 200 response.
                            writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
                            writer.flush();
                        } else {
                            // No extra header; push back.
                            in.unread(headerPeek, 0, bytesPeeked);
                        }
                    }
                }

                // Now that any extra headers have been removed, send version string.
                writer.write("VOTIFIERPLUS " + getVersion());
                writer.newLine();
                writer.flush();

                // Read the 256-byte vote block.
                byte[] block = new byte[256];
                int totalRead = 0;
                while (totalRead < block.length) {
                    int r = in.read(block, totalRead, block.length - totalRead);
                    if (r == -1)
                        break;
                    totalRead += r;
                }

                // Decrypt the block.
                block = RSA.decrypt(block, getKeyPair().getPrivate());
                int position = 0;
                // Check opcode.
                String opcode = readString(block, position);
                position += opcode.length() + 1;
                if (!opcode.equals("VOTE")) {
                    throw new Exception("Unable to decode RSA: invalid opcode " + opcode);
                }
                // Parse vote fields.
                String serviceName = readString(block, position);
                position += serviceName.length() + 1;
                String username = readString(block, position);
                position += username.length() + 1;
                String address = readString(block, position);
                position += address.length() + 1;
                String timeStamp = readString(block, position);
                position += timeStamp.length() + 1;

                // Create the vote.
                final Vote vote = new Vote();
                vote.setServiceName(serviceName);
                vote.setUsername(username);
                vote.setAddress(address);
                vote.setTimeStamp(timeStamp);
                if (timeStamp.equalsIgnoreCase("TestVote")) {
                    log("Test vote received");
                }
                log("Received vote record -> " + vote);

                // Forward the vote to all configured servers.
                for (String server : getServers()) {
                    ForwardServer forwardServer = getServerData(server);
                    if (forwardServer.isEnabled()) {
                        debug("Sending vote to " + server);
                        byte[] encodedPublicKey = Base64.getDecoder().decode(forwardServer.getKey());
                        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
                        X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(encodedPublicKey);
                        PublicKey publicKey = keyFactory.generatePublic(publicKeySpec);
                        String serverIP = forwardServer.getHost();
                        int serverPort = forwardServer.getPort();
                        if (serverIP.length() != 0) {
                            try {
                                String VoteString = "VOTE\n" + vote.getServiceName() + "\n" + vote.getUsername() + "\n"
                                        + vote.getAddress() + "\n" + vote.getTimeStamp() + "\n";
                                SocketAddress sockAddr = new InetSocketAddress(serverIP, serverPort);
                                Socket socket1 = new Socket();
                                socket1.connect(sockAddr, 1000);
                                OutputStream socketOutputStream = socket1.getOutputStream();
                                socketOutputStream.write(encrypt(VoteString.getBytes(), publicKey));
                                socketOutputStream.close();
                                socket1.close();
                            } catch (Exception e) {
                                log("Failed to send vote to " + server + "(" + serverIP + ":" + serverPort + "): "
                                        + vote.toString()
                                        + ", ignore this if server is offline. Enable debug to see the stacktrace");
                                debug(e);
                            }
                        }
                    }
                }
                // Call event on the main thread.
                callEvent(vote);

                // Clean up.
                writer.close();
                in.close();
                socket.close();
            } catch (SocketException ex) {
                logWarning("Protocol error. Ignoring packet - " + ex.getLocalizedMessage());
                debug(ex);
            } catch (BadPaddingException ex) {
                logWarning("Unable to decrypt vote record. Make sure that your public key");
                logWarning("matches the one you gave the server list.");
                debug(ex);
            } catch (Exception ex) {
                logWarning("Exception caught while receiving a vote notification: " + ex.getLocalizedMessage());
                debug(ex);
            }
        }
    }

    /**
     * Checks whether the provided header begins with the binary PROXY protocol v2 signature.
     *
     * @param header the header bytes (must be at least 12 bytes long)
     * @return true if the header matches the v2 signature, false otherwise.
     */
    private boolean isProxyV2(byte[] header) {
        for (int i = 0; i < PROXY_V2_SIGNATURE.length; i++) {
            if (header[i] != PROXY_V2_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    /**
     * Reads a string from a block of data starting at the given offset.
     *
     * @param data   The data to read from.
     * @param offset The starting offset.
     * @return The read string.
     */
    private String readString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder();
        for (int i = offset; i < data.length; i++) {
            if (data[i] == '\n')
                break; // Delimiter reached.
            builder.append((char) data[i]);
        }
        return builder.toString();
    }
    
    /**
     * Reads a line (terminated by LF, with an optional preceding CR) from the input stream.
     * Returns an empty string if the line is empty.
     */
    private String readLine(PushbackInputStream in) throws Exception {
        ByteArrayOutputStream lineBuffer = new ByteArrayOutputStream();
        int b;
        boolean seenCR = false;
        while ((b = in.read()) != -1) {
            if (b == '\r') {
                seenCR = true;
                continue;
            }
            if (b == '\n') {
                break;
            }
            if (seenCR) {
                in.unread(b);
                break;
            }
            lineBuffer.write(b);
        }
        return lineBuffer.toString("ASCII").trim();
    }

    public abstract ForwardServer getServerData(String s);
    public abstract void debug(Exception e);
    public abstract void callEvent(Vote e);

    public byte[] encrypt(byte[] data, PublicKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        return cipher.doFinal(data);
    }
}
