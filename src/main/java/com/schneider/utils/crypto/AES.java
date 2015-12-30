/**
 * 
 */
package com.schneider.utils.crypto;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.schneider.utils.crypto.config.AESConfig;

/**
 * Provides AES encryption functionality.
 * @author Donald McDougal
 *
 */
public class AES extends Base {

	private final AESConfig config = new AESConfig();
	private final IvParameterSpec IV_PARAMETER_SPEC = new IvParameterSpec(config.getIv());
	
	/**
	 * Generates a secret key.
	 * @param keyGenerator The key generator to use to generate the key.
	 * @return The generated secret key.
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 */
	public SecretKey generateSecretKey(char[] password) throws InvalidKeySpecException, NoSuchAlgorithmException {
		SecretKeyFactory factory = SecretKeyFactory.getInstance(config.getKeyFactorySpec());
		KeySpec spec = new PBEKeySpec(password, config.getSalt(), 65536, config.getKeySize());
		SecretKey tmp = factory.generateSecret(spec);
		SecretKey secret = new SecretKeySpec(tmp.getEncoded(), config.getAlgorithm());
		return secret;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.Base#generateCipher(int, java.security.Key)
	 */
	@Override
	protected final Cipher generateCipher(int mode, Key key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		Cipher cipher = Cipher.getInstance(config.getCipherSpec(), this.PROVIDER);
		cipher.init(mode, key, this.IV_PARAMETER_SPEC);
		return cipher;
	}
}
