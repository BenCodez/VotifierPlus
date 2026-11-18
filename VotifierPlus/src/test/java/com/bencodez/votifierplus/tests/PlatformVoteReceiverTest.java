package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.util.Base64;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.logging.Logger;

import javax.crypto.KeyGenerator;
import javax.crypto.Mac;

import org.junit.jupiter.api.Test;

import com.google.gson.JsonObject;
import com.vexsoftware.votifier.ForwardServer;
import com.vexsoftware.votifier.model.Vote;
import com.vexsoftware.votifier.net.PlatformVoteReceiver;
import com.vexsoftware.votifier.net.VoteReceiver;

public class PlatformVoteReceiverTest {

	@Test
	public void boundReceiverDeliversOneAuthenticatedVoteAndReleasesListener() throws Exception {
		Key dummyTokenKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
		var accepted = new LinkedBlockingQueue<Vote>();
		var settings = new PlatformVoteReceiver.Settings("127.0.0.1", 0, "test", false, true,
				null, Map.of("example.test", dummyTokenKey), Set.of(), null, Map.of());
		VoteReceiver bound = PlatformVoteReceiver.bind(settings, Logger.getAnonymousLogger(), accepted::add);
		int port = bound.getServer().getLocalPort();
		try {
			bound.start();
			try (Socket client = new Socket("127.0.0.1", port)) {
				client.setSoTimeout(5000);
				var reader = new BufferedReader(new InputStreamReader(client.getInputStream(), StandardCharsets.UTF_8));
				String greeting = reader.readLine();
				assertTrue(greeting.startsWith("VOTIFIER 2 "));
				JsonObject inner = new JsonObject();
				inner.addProperty("serviceName", "example.test");
				inner.addProperty("username", "TestVoter");
				inner.addProperty("address", "127.0.0.1");
				inner.addProperty("timestamp", "TestTimestamp");
				inner.addProperty("challenge", greeting.substring("VOTIFIER 2 ".length()));
				String payload = inner.toString();

				Mac mac = Mac.getInstance("HmacSHA256");
				mac.init(dummyTokenKey);
				JsonObject envelope = new JsonObject();
				envelope.addProperty("payload", payload);
				envelope.addProperty("signature", Base64.getEncoder()
						.encodeToString(mac.doFinal(payload.getBytes(StandardCharsets.UTF_8))));
				client.getOutputStream().write((envelope + "\n").getBytes(StandardCharsets.UTF_8));
				assertTrue(reader.readLine().contains("\"status\":\"ok\""));
			}
			Vote vote = accepted.poll(5, TimeUnit.SECONDS);
			assertNotNull(vote);
			assertEquals("TestVoter", vote.getUsername());
			assertEquals("127.0.0.1", vote.getSourceAddress());
		} finally {
			bound.shutdown();
			bound.join(5000);
		}
		assertFalse(bound.isAlive());
		assertNull(accepted.poll());
		try (ServerSocket rebound = new ServerSocket()) {
			rebound.bind(new InetSocketAddress("127.0.0.1", port));
		}
	}

	@Test
	public void boundReceiverSnapshotsForwardingAuthentication() throws Exception {
		Key dummyTokenKey = KeyGenerator.getInstance("HmacSHA256").generateKey();
		var target = new ForwardServer(true, "127.0.0.1", 1234, "", dummyTokenKey);
		var settings = new PlatformVoteReceiver.Settings("127.0.0.1", 0, "test", true, true,
				null, Map.of(), Set.of(), null, Map.of("test", target));
		target.setToken(null);
		settings.forwarding().get("test").setToken(null);
		VoteReceiver bound = PlatformVoteReceiver.bind(settings, Logger.getAnonymousLogger(), vote -> {});
		try {
			bound.getServerData("test").setToken(null);
			assertTrue(bound.getServerData("test").isUseTokens());
		} finally {
			bound.shutdown();
		}
	}
}
