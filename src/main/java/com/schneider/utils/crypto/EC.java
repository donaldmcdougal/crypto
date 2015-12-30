/**
 * 
 */
package com.schneider.utils.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;

import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.schneider.utils.crypto.config.ECConfig;

/**
 * Provides Elliptic Curve Cryptography functionality.
 * @author Donald McDougal
 *
 */
public class EC extends Asymmetric {

	private final ECConfig config = new ECConfig();
	
	/**
	 * Creates a key agreement.
	 * @param privateKey The private key used to create a key agreement.
	 * @param publicKey The public key used to create the key agreement.
	 * @return A key agreement.
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws NoSuchProviderException 
	 */
	public KeyAgreement createKeyAgreement(PrivateKey privateKey, PublicKey publicKey) throws NoSuchAlgorithmException, InvalidKeyException, NoSuchProviderException {
		KeyAgreement ka = KeyAgreement.getInstance(config.getKeyAgreementSpec(), this.PROVIDER);
		ka.init(privateKey);
		ka.doPhase(publicKey, true);
		return ka;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Asymmetric#createKeyPairGenerator()
	 */
	@Override
	public KeyPairGenerator createKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getAlgorithm(), this.PROVIDER);
		ECGenParameterSpec ecsp = new ECGenParameterSpec(config.getParameterSpec());
		kpg.initialize(ecsp);
		return kpg;
	}
	
	/**
	 * Generates a secret shared key.
	 * @param keyAgreement The key agreement to use to generate the secret.
	 * @return The secret shared key.
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeyException 
	 * @throws InvalidKeySpecException 
	 */
	public SecretKey generateSecret(KeyAgreement keyAgreement) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
		byte[] bytes = keyAgreement.generateSecret();
		return new SecretKeySpec(Arrays.copyOf(bytes, config.getSecretKeySpecLength() / 8), config.getSecretKeySpec());
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Asymmetric#sign(java.security.PrivateKey, byte[])
	 */
	@Override
	public byte[] sign(PrivateKey privateKey, byte[] bytesToSign) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
		return this.sign(config.getSignatureSpec(), privateKey, bytesToSign);
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Asymmetric#verify(java.security.PublicKey, byte[], byte[])
	 */
	@Override
	public boolean verify(PublicKey publicKey, byte[] signedBytes, byte[] signatureBytes) throws InvalidKeyException, SignatureException, NoSuchAlgorithmException, NoSuchProviderException {
		return this.verify(config.getSignatureSpec(), publicKey, signedBytes, signatureBytes);
	}
}
