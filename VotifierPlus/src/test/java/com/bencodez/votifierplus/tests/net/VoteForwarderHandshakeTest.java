package com.bencodez.votifierplus.tests.net;

import com.vexsoftware.votifier.net.VoteForwarder;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.io.BufferedReader;
import java.io.StringReader;

import org.junit.jupiter.api.Test;

public class VoteForwarderHandshakeTest {
	// Keep the production parser package-private while exercising the same method.
	private static String readHandshakeLine(BufferedReader input) throws Exception {
		Method parser = VoteForwarder.class.getDeclaredMethod("readHandshakeLine", BufferedReader.class);
		parser.setAccessible(true);
		try {
			return (String) parser.invoke(null, input);
		} catch (InvocationTargetException failure) {
			if (failure.getCause() instanceof Exception cause) throw cause;
			if (failure.getCause() instanceof Error cause) throw cause;
			throw new AssertionError(failure.getCause());
		}
	}

	@Test
	public void crlfConsumesBothTerminatorBytesAndPreservesFollowingData() throws Exception {
		BufferedReader input = new BufferedReader(new StringReader("VOTIFIER 2 challenge\r\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(input));
		assertEquals("PAYLOAD", input.readLine());
	}

	@Test
	public void lfAndBareCrPreserveFollowingData() throws Exception {
		BufferedReader lf = new BufferedReader(new StringReader("VOTIFIER 2 challenge\nPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(lf));
		assertEquals("PAYLOAD", lf.readLine());

		BufferedReader cr = new BufferedReader(new StringReader("VOTIFIER 2 challenge\rPAYLOAD\n"));
		assertEquals("VOTIFIER 2 challenge", readHandshakeLine(cr));
		assertEquals("PAYLOAD", cr.readLine());
	}

	@Test
	public void oversizedHandshakeIsStillRejected() {
		BufferedReader input = new BufferedReader(new StringReader("X".repeat(513) + "\r\n"));
		assertThrows(IllegalStateException.class, () -> readHandshakeLine(input));
	}
}
