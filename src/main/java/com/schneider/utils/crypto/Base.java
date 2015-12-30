/**
 * 
 */
package com.schneider.utils.crypto;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 * Provides a base for all encryption.
 * @author Donald McDougal
 *
 */
public abstract class Base {

	protected final String PROVIDER = "BC";
	
	/**
	 * Generates a cipher.
	 * @param mode The mode (encryption or decryption)
	 * @param key The key used to generate the cipher.
	 * @return The generated cipher.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 */
	protected abstract Cipher generateCipher(int mode, Key key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException;

	/**
	 * Decrypts some data using a secret key.
	 * @param key The key used to decrypt the data.
	 * @param data The data to decrypt.
	 * @return The decrypted data.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public final byte[] decrypt(Key key, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = this.generateDecryptionCipher(key);
	    return cipher.doFinal(data);
	}
	
	/**
	 * Decrypts a file.
	 * @param key The key used to decrypt the file.
	 * @param inputFile The input file.
	 * @param outputFile The output file.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 */
	public final void decryptFile(Key key, File inputFile, File outputFile) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IOException {
		
		FileInputStream fis = new FileInputStream(inputFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		FileOutputStream fos = new FileOutputStream(outputFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		Cipher cipher = this.generateDecryptionCipher(key);
	    
	    CipherInputStream cis = new CipherInputStream(bis, cipher);
	    
	    byte[] block = new byte[8];
	    int i;
	    while ((i = cis.read(block)) != -1) {
	    	bos.write(block, 0, i);
	    }
	    cis.close();
	    bis.close();
	    fis.close();
	    bos.close();
	    fos.close();
	}
	
	/**
	 * Encrypts some data using a secret key.
	 * @param key The key used to encrypt data.
	 * @param data The data to encrypt.
	 * @return The encrypted data.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public final byte[] encrypt(Key key, byte[] data) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException, IllegalBlockSizeException, BadPaddingException  {
		Cipher cipher = this.generateEncryptionCipher(key);
		return cipher.doFinal(data);
	}

	/**
	 * Encrypts a file.
	 * @param key The key used to encrypt data.
	 * @param inputFile The input file.
	 * @param outputFile The output file.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchProviderException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws InvalidAlgorithmParameterException
	 * @throws IOException
	 */
	public final void encryptFile(Key key, File inputFile, File outputFile)
			throws NoSuchAlgorithmException, NoSuchProviderException,
			NoSuchPaddingException, InvalidKeyException,
			InvalidAlgorithmParameterException, IOException {
		
		FileInputStream fis = new FileInputStream(inputFile);
		BufferedInputStream bis = new BufferedInputStream(fis);
		FileOutputStream fos = new FileOutputStream(outputFile);
		BufferedOutputStream bos = new BufferedOutputStream(fos);
		
		Cipher cipher = this.generateEncryptionCipher(key);
		
		CipherOutputStream cos = new CipherOutputStream(bos, cipher);
		
		byte[] block = new byte[8];
		int i;
		while ((i = bis.read(block)) != -1) {
			cos.write(block, 0, i);
		}
		cos.close();
		bos.close();
		fos.close();
		bis.close();
		fis.close();
	}
	
	/**
	 * Generates a decryption cipher.
	 * @param key The key used to generate the decryption cipher.
	 * @return The generated cipher.
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	protected final Cipher generateDecryptionCipher(Key key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		return this.generateCipher(Cipher.DECRYPT_MODE, key);
	}

	/**
	 * Generates an encryption cipher.
	 * @param key The key used to generate the encryption cipher.
	 * @return The generated cipher.
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchProviderException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidAlgorithmParameterException 
	 * @throws InvalidKeyException 
	 */
	protected final Cipher generateEncryptionCipher(Key key) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
		return this.generateCipher(Cipher.ENCRYPT_MODE, key);
	}
}
