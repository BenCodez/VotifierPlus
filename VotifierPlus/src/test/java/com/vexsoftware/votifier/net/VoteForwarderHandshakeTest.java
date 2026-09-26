package com.vexsoftware.votifier.net;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.BufferedReader;
import java.io.StringReader;

import org.junit.jupiter.api.Test;

public class VoteForwarderHandshakeTest {
	@Test
	public void crlfConsumesBothTerminatorBytesAndPreservesFollowingData() throws Exception {
		BufferedReader input = new BufferedReader(new StringReader("VOTIFIER 2 challenge\r\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", VoteForwarder.readHandshakeLine(input));
		assertEquals("PAYLOAD", input.readLine());
	}

	@Test
	public void lfAndBareCrPreserveFollowingData() throws Exception {
		BufferedReader lf = new BufferedReader(new StringReader("VOTIFIER 2 challenge\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", VoteForwarder.readHandshakeLine(lf));
		assertEquals("PAYLOAD", lf.readLine());

		BufferedReader cr = new BufferedReader(new StringReader("VOTIFIER 2 challenge\rPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", VoteForwarder.readHandshakeLine(cr));
		assertEquals("PAYLOAD", cr.readLine());
	}

	@Test
	public void oversizedHandshakeIsStillRejected() {
		BufferedReader input = new BufferedReader(new StringReader("X".repeat(513) + "\r\n"));
		assertThrows(IllegalStateException.class, () -> VoteForwarder.readHandshakeLine(input));
	}
}
