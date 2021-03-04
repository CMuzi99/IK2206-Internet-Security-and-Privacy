import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class SessionKey {

	private SecretKey secretkey;
	public SessionKey(Integer keylength) throws NoSuchAlgorithmException {
    
		KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");

		SecureRandom secureRandom = new SecureRandom();
		int keyBitSize = 128;
		keyGenerator.init(keyBitSize, secureRandom); //it takes two parameters: The bit size of the keys to generate, 
		                                             //and a SecureRandom that is used during key generation.
	    secretkey = keyGenerator.generateKey();
	}
	public SessionKey (byte[] keybytes) {
		secretkey = new SecretKeySpec(keybytes, "AES");
	}
	public SecretKey getSecretKey() {
		return secretkey;
	}
	public byte[] getKeyBytes() {
		
		byte[] enCodeFormat = secretkey.getEncoded();
	    return enCodeFormat;
	}

	public String getEncodedKey() {
		byte[] enCodeFormat = secretkey.getEncoded();
		String encodedKey = Base64.getEncoder().encodeToString(enCodeFormat);
		return encodedKey;

}
}
