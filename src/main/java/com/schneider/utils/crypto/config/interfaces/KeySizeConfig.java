/**
 * 
 */
package com.schneider.utils.crypto.config.interfaces;

/**
 * Provides an interface for implementing encryption algorithms with explicit key sizes.
 * @author Donald McDougal
 *
 */
public interface KeySizeConfig {

	/**
	 * Gets the key size.
	 * @return The key size.
	 */
	public int getKeySize();
}
