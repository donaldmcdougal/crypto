# crypto

## donaldmcdougal's Java Cryptography Utilities

Look at the code in this readme to see how to use all of the different encryption.

You also need the java unlimited strength jurisdiction policy files. Make sure to put them in both your JDK and JRE.
Read the readme in the unlimited strength jurisdiction policy files to find out where to put them.

To build a JAR of the project, first make sure Maven is installed, and then,
in a command line, change to the root directory of the project, and then type
'mvn package'.
  
Here is some code to use as an example:

	import java.io.File;
	import java.io.IOException;
	import java.nio.file.Files;
	import java.security.InvalidAlgorithmParameterException;
	import java.security.InvalidKeyException;
	import java.security.KeyPair;
	import java.security.KeyPairGenerator;
	import java.security.NoSuchAlgorithmException;
	import java.security.NoSuchProviderException;
	import java.security.PrivateKey;
	import java.security.PublicKey;
	import java.security.Security;
	import java.security.SignatureException;
	import java.security.spec.InvalidKeySpecException;
	import java.util.Arrays;
	import java.util.List;
	
	import javax.crypto.BadPaddingException;
	import javax.crypto.IllegalBlockSizeException;
	import javax.crypto.KeyAgreement;
	import javax.crypto.NoSuchPaddingException;
	import javax.crypto.SecretKey;
	
	import org.bouncycastle.jce.provider.BouncyCastleProvider;
	
	import com.donaldmcdougal.utils.crypto.AES;
	import com.donaldmcdougal.utils.crypto.EC;
	import com.donaldmcdougal.utils.crypto.RSA;
	
	/**
	 * Provides an example for encrypting and decrypting stuff.
	 *
	 */
	public class App 
	{
	    public static void main( String[] args ) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidAlgorithmParameterException, InvalidKeyException, InvalidKeySpecException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, SignatureException, IOException
	    {
	    	Security.addProvider(new BouncyCastleProvider());
	    	
	    	String dataString = "Here is some decrypted text.";
	        byte[] data = dataString.getBytes("UTF-8");
	        File dataFile = new File("README.md");
	        List<String> dataFileLines = Files.readAllLines(dataFile.toPath());
	        File cipherFile = new File("cipher.md");
	        File plaintextFile = new File("plain.md");
	        
	        System.out.println("***************** EC ******************");
	        EC ecc = new EC();
	        KeyPairGenerator kpg = ecc.createKeyPairGenerator();
	        KeyPair kpa = kpg.generateKeyPair();
	        PrivateKey privka = kpa.getPrivate();
	        PublicKey pubka = kpa.getPublic();
	        KeyPair kpb = kpg.generateKeyPair();
	        PrivateKey privkb = kpb.getPrivate();
	        PublicKey pubkb = kpb.getPublic();
	        KeyAgreement kaa = ecc.createKeyAgreement(privka, pubka);
	        SecretKey ska = ecc.generateSecret(kaa);
	        KeyAgreement kab = ecc.createKeyAgreement(privka, pubkb);
	        SecretKey skb = ecc.generateSecret(kab);
	        KeyAgreement kac = ecc.createKeyAgreement(privkb, pubka);
	        SecretKey skc = ecc.generateSecret(kac);
	        byte[] cipherText = ecc.encrypt(ska, data);
	        String cipherTextString = new String(cipherText, "UTF-8");
	        byte[] plainText = ecc.decrypt(ska, cipherText);
	        String plainTextString = new String(plainText, "UTF-8");
	        ecc.encryptFile(skb, dataFile, cipherFile);
	        ecc.decryptFile(skc, cipherFile, plaintextFile);
	        List<String> plaintextFileLines = Files.readAllLines(plaintextFile.toPath());
	        if (dataFileLines.size() != plaintextFileLines.size()) {
	        	System.out.println("Encryption/Decryption on files did not work properly.  Line count is different.");
	        }
	        else {
	        	for (int i = 0; i < dataFileLines.size(); i++) {
	        		if (!dataFileLines.get(i).equals(plaintextFileLines.get(i))) {
	        			System.out.println("Encryption/Decryption on files did not work properly.  Lines differ.");
	        		}
	        	}
	        }
	        byte[] sig = ecc.sign(privka, data);
	        boolean verified = ecc.verify(pubka, data, sig);
	        System.out.println(dataString);
	        System.out.println(cipherTextString);
	        System.out.println(plainTextString);
	        System.out.println("Key agreement works: " + Arrays.equals(skb.getEncoded(), skc.getEncoded()));
	        Files.delete(cipherFile.toPath());
	        Files.delete(plaintextFile.toPath());
	        System.out.println("Verified: " + verified);
	        System.out.println();
	
	        System.out.println("***************** AES *****************");
	        AES aes = new AES();
	        char[] password = "bootylicious".toCharArray();
	        SecretKey sk2 = aes.generateSecretKey(password);
	        byte[] cipherText2 = aes.encrypt(sk2, data);
	        String cipherTextString2 = new String(cipherText2, "UTF-8");
	        byte[] plainText2 = aes.decrypt(sk2, cipherText2);
	        String plainTextString2 = new String(plainText2, "UTF-8");
	        aes.encryptFile(sk2, dataFile, cipherFile);
	        aes.decryptFile(sk2, cipherFile, plaintextFile);
	        List<String> plaintextFileLines2 = Files.readAllLines(plaintextFile.toPath());
	        if (dataFileLines.size() != plaintextFileLines2.size()) {
	        	System.out.println("Encryption/Decryption on files did not work properly.  Line count is different.");
	        }
	        else {
	        	for (int i = 0; i < dataFileLines.size(); i++) {
	        		if (!dataFileLines.get(i).equals(plaintextFileLines2.get(i))) {
	        			System.out.println("Encryption/Decryption on files did not work properly.  Lines differ.");
	        		}
	        	}
	        }
	        System.out.println(dataString);
	        System.out.println(cipherTextString2);
	        System.out.println(plainTextString2);
	        Files.delete(cipherFile.toPath());
	        Files.delete(plaintextFile.toPath());
	        System.out.println();
	        
	        System.out.println("***************** RSA *****************");
	        RSA rsa = new RSA();
	        KeyPairGenerator kpg2 = rsa.createKeyPairGenerator();
	        KeyPair kp2 = kpg2.generateKeyPair();
	        PrivateKey privk2 = kp2.getPrivate();
	        PublicKey pubk2 = kp2.getPublic();
	        byte[] cipherText3 = rsa.encrypt(pubk2, data);
	        String cipherTextString3 = new String(cipherText3, "UTF-8");
	        byte[] plainText3 = rsa.decrypt(privk2, cipherText3);
	        String plainTextString3 = new String(plainText3, "UTF-8");
	        byte[] sig2 = rsa.sign(privk2, data);
	        boolean verified2 = rsa.verify(pubk2, data, sig2);
	        System.out.println(dataString);
	        System.out.println(cipherTextString3);
	        System.out.println(plainTextString3);
	        System.out.println("Verified: " + verified2);
	    }
	}