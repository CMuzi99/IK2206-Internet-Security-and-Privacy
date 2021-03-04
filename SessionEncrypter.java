import java.io.OutputStream;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;

public class SessionEncrypter {
	private IvParameterSpec ivparameterspec;
	private  SessionKey sessionkey;
	private Cipher cipher;
	public SessionEncrypter(Integer keylength) throws NoSuchAlgorithmException, NoSuchPaddingException, Exception, InvalidAlgorithmParameterException {
		sessionkey = new SessionKey(keylength);
		byte[]IV = new byte[16];
		new SecureRandom().nextBytes(IV); //SecureRandom	
		ivparameterspec = new IvParameterSpec(IV);
		
		//cipher=Cipher.getInstance("AES/CTR/NoPadding");//Creating a Cipher object
		//cipher.init(Cipher.ENCRYPT_MODE,sessionkey.getSecretKey(),ivparameterspec);//Initializing a Cipher object
		
	}
    public SessionEncrypter(byte[] keybytes, byte[] ivbytes) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
    	sessionkey = new SessionKey(keybytes);
        ivparameterspec = new IvParameterSpec(ivbytes);		
		
    }
	public  byte[] getKeyBytes() {
		return sessionkey.getSecretKey().getEncoded();
    }
    public  byte[] getIVBytes() {
		return ivparameterspec.getIV();   	
    }
    public CipherOutputStream openCipherOutputStream(OutputStream output) throws NoSuchAlgorithmException, NoSuchPaddingException, GeneralSecurityException, Exception {
    	cipher=Cipher.getInstance("AES/CTR/NoPadding");//Creating a Cipher object
		cipher.init(Cipher.ENCRYPT_MODE,sessionkey.getSecretKey(),ivparameterspec);//Initializing a Cipher object
        CipherOutputStream cos = new CipherOutputStream(output, cipher);
        return cos;   	
    }
    
}
