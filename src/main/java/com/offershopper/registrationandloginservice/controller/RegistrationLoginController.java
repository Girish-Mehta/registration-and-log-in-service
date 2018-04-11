package com.offershopper.registrationandloginservice.controller;

import java.util.Optional;

import javax.servlet.http.HttpServlet;

import org.jose4j.jwa.AlgorithmConstraints;
import org.jose4j.jwa.AlgorithmConstraints.ConstraintType;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwk.JsonWebKey;
import org.jose4j.lang.JoseException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;

import com.offershopper.registrationandloginservice.LoginInfo;
import com.offershopper.registrationandloginservice.LoginProxyRepo;
import com.offershopper.registrationandloginservice.RegisterInfo;
import com.offershopper.registrationandloginservice.RegisterProxyRepo;

public class RegistrationLoginController {
	@Autowired
	private LoginProxyRepo loginproxy;

	@Autowired
	private RegisterProxyRepo registerproxy;

	@PostMapping("/login")
	public String verifyUser(@RequestBody LoginInfo obj) {
		Optional<LoginInfo> logininfo = loginproxy.findById(obj.getUserId());
		// if user not present return Unauthorized
		if (!logininfo.isPresent()) {
			return "Unauthorized";
		}
		LoginInfo loginobj = logininfo.get();
		// if password not match return Unauthorized
		if (!loginobj.getPassword().equals(obj.getPassword())) {
			return "Unauthorized";
		}
		// return userid and role if userid and password match
		return loginobj.getUserId() + "," + loginobj.getRole();
	}

	// registration for new user
	@PostMapping("/registration")
	public String newUser(@RequestBody RegisterInfo obj) {
		Optional<RegisterInfo> registerinfo = registerproxy.findById(obj.getUserId());
		// if user already present return already exists user
		if (registerinfo.isPresent()) {
			return "Already Exists";
		}
		// save the credential for user and return role
		registerproxy.save(obj);

		// generate token and send email to user with the verification link
		// The shared secret or shared symmetric key represented as a octet sequence
		// JSON Web Key (JWK)
		String userId = obj.getUserId();
		String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
		JsonWebKey jwk = null;
		try {
			jwk = JsonWebKey.Factory.newJwk(jwkJson);
		} catch (JoseException e) {
			return "Already Exists";
		}

		// Create a new Json Web Encryption object
		JsonWebEncryption senderJwe = new JsonWebEncryption();

		// The plaintext of the JWE is the message that we want to encrypt.
		senderJwe.setPlaintext(userId);

		// Set the "alg" header, which indicates the key management mode for this JWE.
		// In this example we are using the direct key management mode, which means
		// the given key will be used directly as the content encryption key.
		senderJwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.DIRECT);

		// Set the "enc" header, which indicates the content encryption algorithm to be
		// used.
		// This example is using AES_128_CBC_HMAC_SHA_256 which is a composition of AES
		// CBC
		// and HMAC SHA2 that provides authenticated encryption.
		senderJwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);

		// Set the key on the JWE. In this case, using direct mode, the key will used
		// directly as
		// the content encryption key. AES_128_CBC_HMAC_SHA_256, which is being used to
		// encrypt the
		// content requires a 256 bit key.
		senderJwe.setKey(jwk.getKey());

		// Produce the JWE compact serialization, which is where the actual encryption
		// is done.
		// The JWE compact serialization consists of five base64url encoded parts
		// combined with a dot ('.') character in the general format of
		// <header>.<encrypted key>.<initialization vector>.<ciphertext>.<authentication
		// tag>
		// Direct encryption doesn't use an encrypted key so that field will be an empty
		// string
		// in this case.
		try {
			String compactSerialization = senderJwe.getCompactSerialization();
		} catch (JoseException e) {
			return "Already Exists";
		}

		// send link to email

		return obj.getUserId() + "," + obj.getRole();
	}

	@GetMapping("/{token}")
	public String verifyUser(@PathVariable String token) {
		// decrypt token and get the user email from it
		String userId = null;
		
		// The shared secret or shared symmetric key represented as a octet sequence
		// JSON Web Key (JWK)
		String jwkJson = "{\"kty\":\"oct\",\"k\":\"Fdh9u8rINxfivbrianbbVT1u232VQBZYKx1HGAGPt2I\"}";
		JsonWebKey jwk = null;
		try {
			jwk = JsonWebKey.Factory.newJwk(jwkJson);
		} catch (JoseException e) {
			return "Unverified";
		}

		// That other party, the receiver, can then use JsonWebEncryption to decrypt the
		// message.
		JsonWebEncryption receiverJwe = new JsonWebEncryption();

		// Set the algorithm constraints based on what is agreed upon or expected from
		// the sender
		AlgorithmConstraints algConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
				KeyManagementAlgorithmIdentifiers.DIRECT);
		receiverJwe.setAlgorithmConstraints(algConstraints);
		AlgorithmConstraints encConstraints = new AlgorithmConstraints(ConstraintType.WHITELIST,
				ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
		receiverJwe.setContentEncryptionAlgorithmConstraints(encConstraints);

		// Set the compact serialization on new Json Web Encryption object
		try {
			receiverJwe.setCompactSerialization(token);
		} catch (JoseException e) {
			return "Unverified";
		}

		// Symmetric encryption, like we are doing here, requires that both parties have
		// the same key.
		// The key will have had to have been securely exchanged out-of-band somehow.
		receiverJwe.setKey(jwk.getKey());

		// Get the message that was encrypted in the JWE. This step performs the actual
		// decryption steps.
		try {
			userId = receiverJwe.getPlaintextString();
		} catch (JoseException e) {
			return "Unverified";
		}

		// compare userId with database
		Optional<RegisterInfo> registerinfo = registerproxy.findById(userId);
		// if user does not exist
		if (registerinfo.isPresent()) {
			// return user not verified
			return "Unverified";
		}
		
		// if verified variable is true then return link expired
		
		// else
		// set verified variable to true
		
		// return user verified
		return "Verified";
	}
}
