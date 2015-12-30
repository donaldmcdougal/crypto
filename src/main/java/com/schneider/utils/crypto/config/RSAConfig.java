/**
 * 
 */
package com.schneider.utils.crypto.config;

import com.schneider.utils.crypto.config.interfaces.AsymmetricConfig;
import com.schneider.utils.crypto.config.interfaces.BaseConfig;
import com.schneider.utils.crypto.config.interfaces.KeySizeConfig;

/**
 * Provides configuration options for RSA.  Elliptic curve cryptography is recommended instead of this.
 * @author Donald McDougal
 *
 */
public class RSAConfig implements BaseConfig, AsymmetricConfig, KeySizeConfig {

	private final String algorithm = "RSA";
	private final int keySize = 4096;
	private final String signatureSpec = "SHA512withRSA";
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.BaseConfig#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.KeySizeConfig#getKeySize()
	 */
	@Override
	public int getKeySize() {
		return keySize;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.AsymmetricConfig#getSignatureSpec()
	 */
	@Override
	public String getSignatureSpec() {
		return signatureSpec;
	}
}
