import java.io.FileInputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HandshakeCrypto {
	private static Cipher cipher;
	public static byte[] encrypt(byte[] plaintext, Key key) throws IllegalBlockSizeException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, GeneralSecurityException  {
		cipher=Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, key);
		return cipher.doFinal(plaintext);
	}

	public static byte[] decrypt(byte[] ciphertext, Key key) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		 cipher=Cipher.getInstance("RSA");//Creating a Cipher object
 		 cipher.init(Cipher.DECRYPT_MODE,key);
 		byte[] decipheredText = cipher.doFinal(ciphertext);
 		return decipheredText;
		
	}
	public static PublicKey getPublicKeyFromCertFile(String certfile) throws Exception {
		//CertFile = new GetCertificate(certfile);
		FileInputStream CAfile = new FileInputStream(certfile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate((CAfile));
        PublicKey PubKey =  cert.getPublicKey();
        return PubKey;
	}
	
	public static PrivateKey getPrivateKeyFromKeyFile(String keyfile) throws Exception {
		Path path = Paths.get(keyfile);
		byte[] privKeyByteArray = Files.readAllBytes(path);

		PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(privKeyByteArray);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		PrivateKey myPrivKey = keyFactory.generatePrivate(keySpec);
		return myPrivKey;
	}
}