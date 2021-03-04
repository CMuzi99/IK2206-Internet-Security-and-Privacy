import java.io.InputStream;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionDecrypter {
     private Cipher cipher;
     private IvParameterSpec ivparameterspec;
     private SessionKey key;
	 public SessionDecrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	 key = new SessionKey(keybytes);
         ivparameterspec = new IvParameterSpec(ivbytes);		
 		 cipher=Cipher.getInstance("AES/CTR/NoPadding");//Creating a Cipher object
 		 cipher.init(Cipher.DECRYPT_MODE,key.getSecretKey(),ivparameterspec);//Initializing a Cipher object
     }
     public CipherInputStream openCipherInputStream(InputStream input) {
    	 CipherInputStream cis = new CipherInputStream(input, cipher);
    	 return cis;
     }
}
