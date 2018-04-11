package com.offershopper.registrationandloginservice;

import javax.validation.constraints.Size;

import org.springframework.data.annotation.Id;
import org.springframework.data.mongodb.core.mapping.Document;

@Document(collection = "RegisterInfo")
public class RegisterInfo {
	
	private String FirstName;
	private String LastName;
	@Id
	private String userId;
	private String MobileNo;
	@Size(min = 6, max = 12, message = "Password should be atleast of length 6 and max of length 12")
	private String password;
	private String role;
	
	
	
	public String getRole() {
		return role;
	}
	public void setRole(String role) {
		this.role = role;
	}
	public RegisterInfo(String firstName, String lastName, String userId, String mobileNo, String password,String role) {
		super();
		this.FirstName = firstName;
		this.LastName = lastName;
		this.userId = userId;
		this.MobileNo = mobileNo;
		this.password = password;
		this.role=role;
	}
	public String getFirstName() {
		return FirstName;
	}
	public void setFirstName(String firstName) {
		FirstName = firstName;
	}
	public String getLastName() {
		return LastName;
	}
	public void setLastName(String lastName) {
		LastName = lastName;
	}
	public String getUserId() {
		return userId;
	}
	public void setUserId(String userId) {
		this.userId = userId;
	}
	public String getMobileNo() {
		return MobileNo;
	}
	public void setMobileNo(String mobileNo) {
		MobileNo = mobileNo;
	}
	public String getPassword() {
		return password;
	}
	public void setPassword(String password) {
		this.password = password;
	}
	
	

}
