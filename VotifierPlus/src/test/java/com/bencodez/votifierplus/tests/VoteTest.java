package com.bencodez.votifierplus.tests;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

import com.vexsoftware.votifier.model.Vote;

public class VoteTest {
	@Test
	public void serviceNameIsSetCorrectly() {
		Vote vote = new Vote();
		vote.setServiceName("TestService");
		assertEquals("TestService", vote.getServiceName());
	}

	@Test
	public void usernameIsSetCorrectly() {
		Vote vote = new Vote();
		vote.setUsername("TestUser");
		assertEquals("TestUser", vote.getUsername());
	}

	@Test
	public void usernameIsTruncatedIfTooLong() {
		Vote vote = new Vote();
		vote.setUsername("ThisUsernameIsWayTooLong");
		assertEquals("ThisUsernameIsWa", vote.getUsername());
	}

	@Test
	public void addressIsSetCorrectly() {
		Vote vote = new Vote();
		vote.setAddress("127.0.0.1");
		assertEquals("127.0.0.1", vote.getAddress());
	}

	@Test
	public void timeStampIsSetCorrectly() {
		Vote vote = new Vote();
		vote.setTimeStamp("2023-10-10 10:10:10");
		assertEquals("2023-10-10 10:10:10", vote.getTimeStamp());
	}

	@Test
	public void toStringReturnsCorrectFormat() {
		Vote vote = new Vote("TestService", "TestUser", "127.0.0.1", "2023-10-10 10:10:10");
		assertEquals("Vote (from:TestService username:TestUser address:127.0.0.1 timeStamp:2023-10-10 10:10:10)",
				vote.toString());
	}
}
