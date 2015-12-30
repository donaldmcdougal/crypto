/**
 * 
 */
package com.schneider.utils.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;

/**
 * @author jschneider
 *
 */
public abstract class Asymmetric extends Base {

	/**
	 * Creates a key pair generator.
	 * @return The key pair generator.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws InvalidAlgorithmParameterException
	 */
	public abstract KeyPairGenerator createKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException;
	
	/**
	 * Signs some bytes.
	 * @param privateKey The private key to use to sign the bytes.
	 * @param bytesToSign The bytes to sign.
	 * @return The signature bytes.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public abstract byte[] sign(PrivateKey privateKey, byte[] bytesToSign) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException;
	
	/**
	 * Verifies a signature.
	 * @param publicKey The public key to use to verify the signature.
	 * @param signedBytes The signed bytes to verify.
	 * @param signatureBytes The bytes of the signature.
	 * @return <code>true</code> if the signature was verified; <code>false</code> otherwise.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	public abstract boolean verify(PublicKey publicKey, byte[] signedBytes, byte[] signatureBytes) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException;
	
	/**
	 * Generates a key pair.
	 * @param kpg The KeyPairGenerator to use to create the key pair.
	 * @return The key pair.
	 */
	public final KeyPair generateKeyPair(KeyPairGenerator kpg) {
		return kpg.generateKeyPair();
	}

	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Base#generateCipher(int, java.security.Key)
	 */
	protected final Cipher generateCipher(int mode, Key key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(key.getAlgorithm(), this.PROVIDER);
		cipher.init(mode, key);
		return cipher;
	}
	
	/**
	 * Signs some bytes.
	 * @param signatureSpec The signature specification.
	 * @param privateKey The private key to use to sign the bytes.
	 * @param bytesToSign The bytes to sign.
	 * @return The signature bytes.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	protected final byte[] sign(String signatureSpec, PrivateKey privateKey, byte[] bytesToSign) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
		Signature signature = this.createSignature(signatureSpec);
		signature.initSign(privateKey);
		signature.update(bytesToSign);
		byte[] bytesSig = signature.sign();
		return bytesSig;
	}
	
	/**
	 * Verifies a signature.
	 * @param signatureSpec The signature specification.
	 * @param publicKey The public key to use to verify the signature.
	 * @param signedBytes The signed bytes to verify.
	 * @param signatureBytes The bytes of the signature.
	 * @return <code>true</code> if the signature was verified; <code>false</code> otherwise.
	 * @throws InvalidKeyException
	 * @throws SignatureException
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	protected final boolean verify(String signatureSpec, PublicKey publicKey, byte[] signedBytes, byte[] signatureBytes) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
		Signature signature = this.createSignature(signatureSpec);
		signature.initVerify(publicKey);
		signature.update(signedBytes);
		boolean result = signature.verify(signatureBytes);
		return result;
	}
	
	/**
	 * Creates a signature and initializes it with a private key.
	 * @param signatureSpec The signature specification.
	 * @return A signature.
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 */
	private final Signature createSignature(String signatureSpec) throws NoSuchAlgorithmException, NoSuchProviderException {
		Signature sig = Signature.getInstance(signatureSpec, this.PROVIDER);
		return sig;
	}
}
