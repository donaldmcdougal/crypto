/**
 * 
 */
package com.schneider.utils.crypto.config;

import com.schneider.utils.crypto.config.interfaces.BaseConfig;
import com.schneider.utils.crypto.config.interfaces.KeySizeConfig;

/**
 * Provides configuration options for AES.  If you are sending this object over the wire, you NEED to do it over a secure channel.
 * If two users have to agree on a key, using elliptic curve cryptography is recommended.  Otherwise, encrypting files is the
 * normal use case for AES.
 * @author Donald McDougal
 *
 */
public class AESConfig implements BaseConfig, KeySizeConfig {

	private final String algorithm = "AES";
	private final String keyFactorySpec = "PBKDF2WithHmacSHA256";
	private final String cipherSpec = "AES/CBC/PKCS5Padding";
	private final int keySize = 256;
	private final byte[] salt = {9, 75, 84, 56, 47, -19, -19, 0};
	private final byte[] iv = {-22, -87, -88, -97, -59, 103, 100, -61, -111, -116, -66, -115, 84, 12, -68, -118};
	
	/**
	 * Gets the key factory specification.
	 * @return The name of the key factory specification.
	 */
	public String getKeyFactorySpec() {
		return keyFactorySpec;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.BaseConfig#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * Gets the cipher specification.
	 * @return The name of the cipher specification.
	 */
	public String getCipherSpec() {
		return cipherSpec;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.KeySizeConfig#getKeySize()
	 */
	@Override
	public int getKeySize() {
		return keySize;
	}
	
	/**
	 * Gets the password salt.
	 * @return The password salt.
	 */
	public byte[] getSalt() {
		return salt;
	}
	
	/**
	 * Gets the initialization vector.
	 * @return The initialization vector.
	 */
	public byte[] getIv() {
		return iv;
	}
}
