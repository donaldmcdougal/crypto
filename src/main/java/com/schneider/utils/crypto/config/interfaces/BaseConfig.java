/**
 * 
 */
package com.schneider.utils.crypto.config.interfaces;

/**
 * Provides a base class for all cryptography configuration.
 * @author Donald McDougal
 *
 */
public interface BaseConfig {

	/**
	 * Gets the name of the algorithm used for encryption and decryption.
	 * @return The name of the algorithm used for encryption and decryption.
	 */
	public String getAlgorithm();
}
