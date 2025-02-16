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
 * This version supports multiple connection wrappers:
 * 1. Direct TCP (no extra header)
 * 2. PROXY protocol v1 (text-based): if the data begins with "PROXY", read and discard that header line,
 *    then drain any extra CR/LF characters.
 * 3. PROXY protocol v2 (binary): if the first 12 bytes match the v2 signature, read and discard the full binary header.
 * 4. HTTP CONNECT tunneling: if the connection begins with "CONNECT", read/discard the CONNECT request
 *    and send a "200 Connection Established" response.
 * 
 * After discarding any extra header, the normal vote protocol is performed.
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

/**
 * The vote receiving server.
 * 
 * This version supports multiple connection wrappers:
 * 1. Direct TCP (no extra header)
 * 2. PROXY protocol v1 (text-based): if the data begins with "PROXY", read and discard that header line,
 *    then drain any extra CR/LF characters.
 * 3. PROXY protocol v2 (binary): if the first 12 bytes match the v2 signature, read and discard the full binary header.
 * 4. HTTP CONNECT tunneling: if the connection begins with "CONNECT", read/discard the CONNECT request
 *    and send a "200 Connection Established" response.
 * 
 * After discarding any extra header, the normal vote protocol is performed.
 */
public abstract class VoteReceiver extends Thread {

    private final String host;
    private final int port;
    private ServerSocket server;
    private boolean running = true;

    // Expected 12-byte signature for PROXY protocol v2.
    private static final byte[] PROXY_V2_SIGNATURE = new byte[] {
        0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A
    };

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
            debug("Bound to " + server.getInetAddress().getHostAddress() + ":" + server.getLocalPort());
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

    public abstract Set<String> getServers();
    public abstract KeyPair getKeyPair();

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

    @Override
    public void run() {
        while (running) {
            try (Socket socket = server.accept()) {
                socket.setSoTimeout(5000); // Timeout for slow connections.
                PushbackInputStream in = new PushbackInputStream(socket.getInputStream(), 512);
                BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));

                // Read up to 32 bytes for header detection.
                byte[] peekBuffer = new byte[32];
                int bytesPeeked = 0;
                while (bytesPeeked < peekBuffer.length) {
                    int r = in.read(peekBuffer, bytesPeeked, peekBuffer.length - bytesPeeked);
                    if (r == -1) break;
                    bytesPeeked += r;
                    if (bytesPeeked >= 16) break;
                }
                if (bytesPeeked > 0) {
                    // Log hex dump for debugging.
                    StringBuilder hexDump = new StringBuilder();
                    for (int i = 0; i < bytesPeeked; i++) {
                        hexDump.append(String.format("%02X ", peekBuffer[i]));
                    }
                    debug("Peeked header bytes (" + bytesPeeked + "): " + hexDump.toString().trim());

                    if (bytesPeeked >= 12 && isProxyV2(peekBuffer)) {
                        // PROXY protocol v2 detected.
                        int addrLength = ((peekBuffer[14] & 0xFF) << 8) | (peekBuffer[15] & 0xFF);
                        int totalV2HeaderLength = 16 + addrLength;
                        int remaining = totalV2HeaderLength - bytesPeeked;
                        byte[] discard = new byte[remaining];
                        int readRemaining = 0;
                        while (readRemaining < remaining) {
                            int r = in.read(discard, readRemaining, remaining - readRemaining);
                            if (r == -1)
                                break;
                            readRemaining += r;
                        }
                        if (readRemaining != remaining) {
                            throw new Exception("Incomplete PROXY protocol v2 header");
                        }
                        debug("Discarded PROXY protocol v2 header (total " + totalV2HeaderLength + " bytes)");
                    } else {
                        String headerString = new String(peekBuffer, 0, bytesPeeked, "ASCII");
                        if (headerString.startsWith("PROXY")) {
                            // PROXY protocol v1.
                            in.unread(peekBuffer, 0, bytesPeeked);
                            ByteArrayOutputStream headerLine = new ByteArrayOutputStream();
                            byte[] buf = new byte[1];
                            while (in.read(buf) != -1) {
                                headerLine.write(buf[0]);
                                if (buf[0] == '\n')
                                    break;
                            }
                            String proxyHeader = headerLine.toString("ASCII").trim();
                            debug("Discarded PROXY (v1) header: " + proxyHeader);
                            
                            // Drain any extra CR/LF characters.
                            int extra;
                            while ((extra = in.read()) != -1) {
                                if (extra != '\r' && extra != '\n') {
                                    in.unread(extra);
                                    break;
                                }
                            }
                        } else if (headerString.startsWith("CONNECT")) {
                            // HTTP CONNECT tunneling.
                            in.unread(peekBuffer, 0, bytesPeeked);
                            String connectLine = readLine(in);
                            debug("Received CONNECT request: " + connectLine);
                            String line;
                            while (!(line = readLine(in)).isEmpty()) {
                                debug("Discarding header: " + line);
                            }
                            writer.write("HTTP/1.1 200 Connection Established\r\n\r\n");
                            writer.flush();
                        } else {
                            // No extra header detected.
                            in.unread(peekBuffer, 0, bytesPeeked);
                        }
                    }
                }

                // Send version handshake.
                writer.write("VOTIFIERPLUS " + getVersion());
                writer.newLine();
                writer.flush();

                // Read exactly 256 bytes for the vote block.
                byte[] block = new byte[256];
                int totalRead = 0;
                while (totalRead < block.length) {
                    int r = in.read(block, totalRead, block.length - totalRead);
                    if (r == -1)
                        break;
                    totalRead += r;
                }
                if (totalRead != 256) {
                    throw new Exception("Incomplete vote block; expected 256 bytes but received " + totalRead);
                }

                byte[] decrypted;
                try {
                    decrypted = RSA.decrypt(block, getKeyPair().getPrivate());
                } catch (BadPaddingException e) {
                    // Log hex dump for diagnosis.
                    StringBuilder blockHex = new StringBuilder();
                    for (byte b : block) {
                        blockHex.append(String.format("%02X ", b));
                    }
                    logWarning("Decryption failed. Raw vote block (hex): " + blockHex.toString().trim());
                    throw e;
                }
                
                int position = 0;
                String opcode = readString(decrypted, position);
                position += opcode.length() + 1;
                if (!opcode.equals("VOTE")) {
                    throw new Exception("Unable to decode RSA: invalid opcode " + opcode);
                }
                String serviceName = readString(decrypted, position);
                position += serviceName.length() + 1;
                String username = readString(decrypted, position);
                position += username.length() + 1;
                String address = readString(decrypted, position);
                position += address.length() + 1;
                String timeStamp = readString(decrypted, position);
                position += timeStamp.length() + 1;

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
                                        + vote.toString() + ", ignore this if server is offline. Enable debug to see the stacktrace");
                                debug(e);
                            }
                        }
                    }
                }
                callEvent(vote);
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

    private boolean isProxyV2(byte[] header) {
        for (int i = 0; i < PROXY_V2_SIGNATURE.length; i++) {
            if (header[i] != PROXY_V2_SIGNATURE[i]) {
                return false;
            }
        }
        return true;
    }

    private String readString(byte[] data, int offset) {
        StringBuilder builder = new StringBuilder();
        for (int i = offset; i < data.length; i++) {
            if (data[i] == '\n')
                break;
            builder.append((char) data[i]);
        }
        return builder.toString();
    }
    
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
