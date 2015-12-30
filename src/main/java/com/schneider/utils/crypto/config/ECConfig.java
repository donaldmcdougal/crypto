/**
 * 
 */
package com.schneider.utils.crypto.config;

import com.schneider.utils.crypto.config.interfaces.AsymmetricConfig;
import com.schneider.utils.crypto.config.interfaces.BaseConfig;

/**
 * Provides configuration options for ECC.
 * @author Donald McDougal
 *
 */
public class ECConfig implements BaseConfig, AsymmetricConfig {

	private final String algorithm = "EC";
	private final String parameterSpec = "secp521r1"; //a 521 bit key.
	private final String keyAgreementSpec = "ECDH";
	private final String signatureSpec = "SHA512withECDSA";
	private final String secretKeySpec = "AES";
	private final int secretKeySpecLength = 256;
	
	/*
	 Curves over Fp - recommended by NIST.
	 – 192 bits: secp192k1 and secp192r1.
	 – 224 bits: secp224k1 and secp224r1.
	 – 256 bits: secp256k1 and secp256r1.
	 – 384 bits: secp384r1.
	 – 521 bits: secp521r1.
	 */
	/*
	 Curves over F2m
	 – 163 bits: sect163k1, sect163r1, and sect163r2.
	 – 233 bits: sect233k1 and sect233r1.
	 – 239 bits: sect239k1.
	 – 283 bits: sect283k1 and sect283r1.
	 – 409 bits: sect409k1 and sect409r1.
	 – 571 bits: sect571k1 and sect571r1.
	 */
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.BaseConfig#getAlgorithm()
	 */
	@Override
	public String getAlgorithm() {
		return algorithm;
	}
	
	/**
	 * Gets the name of the elliptic curve to use for cryptography.
	 * @return The name of the elliptic curve to use for cryptography.
	 */
	public String getParameterSpec() {
		return parameterSpec;
	}
	
	/**
	 * Gets the name of the type of key agreement to use.
	 * @return The name of the type of key agreement to use.
	 */
	public String getKeyAgreementSpec() {
		return keyAgreementSpec;
	}
	
	/*
	 * (non-Javadoc)
	 * @see com.schneider.utils.crypto.config.AsymmetricConfig#getSignatureSpec()
	 */
	@Override
	public String getSignatureSpec() {
		return signatureSpec;
	}
	
	/**
	 * Gets the name of the specification to use for shared secret keys.
	 * @return The name of the specification to use for shared secret keys.
	 */
	public String getSecretKeySpec() {
		return secretKeySpec;
	}

	/**
	 * Gets the length of the key for shared secret keys.
	 * @return The length of the key for shared secret keys.
	 */
	public int getSecretKeySpecLength() {
		return secretKeySpecLength;
	}
}
