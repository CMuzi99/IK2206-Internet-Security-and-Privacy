import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

public class VerifyCertificate {
	
	//private static  java.security.cert.Certificate certificate;
	//private static  java.security.cert.Certificate usercert;

	public static void main(String args[]) throws Exception, FileNotFoundException  {

		//String cerPath = "D:\\KTH\\IK2206-Internet security and privacy\\ztrpem\\CA.pem";
		//String userPath = "D:\\KTH\\IK2206-Internet security and privacy\\ztrpem\\user.pem";
		String CACert = args[0];
		String userCert = args[1];
		//Verifycertificate(cerPath,userPath);
		PublicKey CAkey = getCertification(CACert).getPublicKey();
        Verifycertificate(getCertification(CACert), getCertification(userCert),CAkey);

	}
	/*public static void Verifycertificate(String cerPath, String userPath) throws CertificateException, FileNotFoundException, InvalidKeyException, NoSuchAlgorithmException, Exception, SignatureException {
		certificate = GetCertificate(cerPath);
		usercert = GetCertificate(userPath);
		System.out.println("CA's DN information:"+((X509Certificate) certificate).getSubjectDN().getName());
		System.out.println("User's DN information:"+((X509Certificate) usercert).getSubjectDN().getName());
        PublicKey publicKey = certificate.getPublicKey();
        certificate.verify(publicKey);
        boolean CAvalid = Verifyvalid(cerPath);

        usercert.verify(publicKey);
        boolean Uservalid = Verifyvalid(userPath);

        if(CAvalid&&Uservalid) {
        	System.out.println("Pass");
        }
        
	}*/
	public static void Verifycertificate(X509Certificate CACert, X509Certificate usercert,PublicKey CAkey) throws InvalidKeyException, CertificateException, NoSuchAlgorithmException, NoSuchProviderException, SignatureException {
		System.out.println("CA's DN information:"+((X509Certificate) CACert).getSubjectDN().getName());
		System.out.println("User's DN information:"+((X509Certificate) usercert).getSubjectDN().getName());
        //PublicKey publicKey = CACert.getPublicKey();
        CACert.verify(CAkey);
        CACert.checkValidity();

        usercert.verify(CAkey);
        usercert.checkValidity();
	}
/*	public final static  java.security.cert.Certificate GetCertificate(String Path) throws CertificateException, FileNotFoundException {
		File file = new File(Path);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate)cf.generateCertificate(new FileInputStream(file));
        return cert;
		
	}*/
	public static X509Certificate getCertification(String filename) throws CertificateException, IOException {
        InputStream inStream = new FileInputStream(filename);
        CertificateFactory certificatefactory = CertificateFactory.getInstance("X509");
        X509Certificate cert = (X509Certificate)certificatefactory.generateCertificate(inStream);
        inStream.close();
        return cert;
    }
	 public static X509Certificate createCertification(String certificate) throws CertificateException {
	        CertificateFactory certificatefactory = CertificateFactory.getInstance("X.509");
	        byte [] CertByte = java.util.Base64.getDecoder().decode(certificate);
	        InputStream inStream = new ByteArrayInputStream(CertByte);
	        return (X509Certificate) certificatefactory.generateCertificate(inStream);
	    }
//-------------------------get public key-------------------------	
//	public static PublicKey getPublicKey(String cerPath) {
//		PublicKey publickey = certificate.getPublicKey();
//		return publickey;
//	}
/*	public static boolean verify(PublicKey Key) {
		boolean isVerified;
		try {
			isVerified = true;
			
		}catch(Exception e) {
			isVerified = false;
		}
		return isVerified;
	}
	public static boolean Verifyvalid(String cerPath){
		boolean isValid ;
        try {
            X509Certificate x509Certificate =(X509Certificate) GetCertificate(cerPath);
            x509Certificate.checkValidity();
            isValid = true;
        } catch (Exception e) {
            isValid = false;
        }
        return isValid;
	}*/
}
