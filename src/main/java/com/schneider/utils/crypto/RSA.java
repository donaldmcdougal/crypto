/**
 * 
 */
package com.schneider.utils.crypto;

import java.security.InvalidKeyException;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;

import com.schneider.utils.crypto.config.RSAConfig;

/**
 * Provides RSA encryption.  Encryption will not work with files or strings larger than 512 bytes.
 * @author Donald McDougal
 *
 */
public class RSA extends Asymmetric {

	private final RSAConfig config = new RSAConfig();
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Asymmetric#createKeyPairGenerator()
	 */
	@Override
	public KeyPairGenerator createKeyPairGenerator() throws NoSuchAlgorithmException, NoSuchProviderException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(config.getAlgorithm(), this.PROVIDER);
		kpg.initialize(config.getKeySize());
		return kpg;
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
