/**
 * 
 */
package com.schneider.utils.crypto.config.interfaces;

/**
 * An interface that defines what asymmetric encryption configurations should define.
 * @author Donald McDougal
 *
 */
public interface AsymmetricConfig {

	/**
	 * Gets the name of the signature specification.
	 * @return The name of the signature specification.
	 */
	public String getSignatureSpec();
}
