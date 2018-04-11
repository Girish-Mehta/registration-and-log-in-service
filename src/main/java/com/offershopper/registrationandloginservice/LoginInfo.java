package com.offershopper.registrationandloginservice;

import javax.validation.constraints.Size;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "LoginInfo")
public class LoginInfo {
	
	@Id
	private String userId;
	@Size(min = 6, max = 12, message = "Password should be atleast of length 6 and max of length 12")
	private String password;
	private String role;
	
	
	public LoginInfo() {
		super();
	}
	
	public LoginInfo(String userId, String password, String role) {
		super();
		this.userId = userId;
		this.password = password;
		this.role = role;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	

}
