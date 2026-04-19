package com.vexsoftware.votifier.net;

import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
public class VoteRequest {

	private String serviceName;
	private String username;
	private String address;
	private String timeStamp;
}