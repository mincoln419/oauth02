package com.ideatec.oauth2client.controller;

public enum GroupIds {
	ADMIN(""), NORMAL("");

	private String groupName;

	private GroupIds(String groupName) {
		this.groupName = groupName;
	}


}
