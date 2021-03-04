/**
 * Client side of the handshake.
 */

import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.io.IOException;

public class ClientHandshake {
    /*
     * The parameters below should be learned by the client
     * through the handshake protocol. 
     */
    
    /* Session host/port  */
    public static String sessionHost = "localhost";
    public static int sessionPort = 12345; 
    public static byte[] sessionKey;
    public static byte[] sessionIV;
    public static X509Certificate serverCert;
  
    //private SessionEncrypter sessionEncrypter;
    //private SessionDecrypter sessionDecrypter;

    /* Security parameters key/iv should also go here. Fill in! */

    public ClientHandshake(Socket handshakeSocket) throws Exception{
    	    clientHello("ClientHello",ForwardClient.arguments.get("usercert"),handshakeSocket);
    	    clientVerify(ForwardClient.arguments.get("cacert"), handshakeSocket);
    	    forwardMessage(ForwardClient.arguments.get("targethost"),ForwardClient.arguments.get("targetport"),handshakeSocket);
    	    finishHandshake(handshakeSocket, ForwardClient.arguments.get("key"));
    
    		/*Handshake handshake = new Handshake();
			
	    	/*handshake.clientHello(ForwardClient.arguments.get("usercert"), handshakeSocket);
	    	handshake.clientVerify(ForwardClient.arguments.get("cacert"), handshakeSocket);
	    	
	    	handshake.forwardMessage(ForwardClient.arguments.get("targethost"),ForwardClient.arguments.get("targetport"),handshakeSocket);
	    	handshake.finishHandshake(handshakeSocket, ForwardClient.arguments.get("key"));
	    	*/
	    	handshakeSocket.close();
    }
	        /*sessionEncrypter = handshake.getSessionEncrypter();
	        sessionDecrypter = handshake.getSessionDecrypter();
	    	*/
	    	 private void clientHello(String messageType,String usercert, Socket handshakeSocket) throws CertificateException, IOException {
	    	        HandshakeMessage clienthello = new HandshakeMessage();
	    	       // InputStream clientCertIn = new FileInputStream(usercert);
	    	      //  clientCert = (X509Certificate)cf.generateCertificate(clientCertIn);
	    	      //  byte[] clientCertNobase64 = clientCert.getEncoded();
	    	        String clientCertString = Base64.getEncoder().encodeToString(VerifyCertificate.getCertification(usercert).getEncoded());
	    	        clienthello.putParameter("MessageType", "ClientHello");
	    	        clienthello.putParameter("Certificate", clientCertString);
	    	        clienthello.send(handshakeSocket);
	    	    }
	    	 private void clientVerify(String CAcert, Socket handshakeSocket) throws Exception {
	    	        HandshakeMessage fromServerHello = new HandshakeMessage();
	    	        fromServerHello.recv(handshakeSocket);
	    	        if (fromServerHello.getParameter("MessageType").equals("ServerHello")) {
	    	        	
	    	          /*  String serverCertString = fromServerHello.getParameter("Certificate");
	    	            byte[] serverCertBytes = Base64.getDecoder().decode(serverCertString);
	    	            InputStream serverCertIn = new ByteArrayInputStream(serverCertBytes);
	    	            serverCert = (X509Certificate) cf.generateCertificate(serverCertIn);

	    	            InputStream CACertIn = new FileInputStream(cacert);
	    	            CACert = (X509Certificate) cf.generateCertificate(CACertIn);

	    	            VerifyCertificate.Verifycertificate(CACert,serverCert);
*/
	    	        	 PublicKey CAkey = VerifyCertificate.getCertification(CAcert).getPublicKey();
	    	                serverCert = VerifyCertificate.createCertification(fromServerHello.getParameter("Certificate"));
	    	                VerifyCertificate.Verifycertificate(VerifyCertificate.getCertification(CAcert), serverCert, CAkey);
	    	            System.out.println("Server certificate is validated.");
	    	        }
	    	          else {
	    	            System.out.println("Client Verify Server certificate Error");
	    	            handshakeSocket.close();
	    	        }
	    	     }
	    	 private void forwardMessage(String targetHost, String targetPort, Socket handshakeSocket) throws IOException {
	         	HandshakeMessage clientforward = new HandshakeMessage();
	         
	         	clientforward.putParameter("MessageType", "Forward");
	         	clientforward.putParameter("TargetHost", targetHost);
	         	clientforward.putParameter("TargetPort", targetPort);
	         	clientforward.send(handshakeSocket);        
	     }
	    	 private void finishHandshake(Socket handshakeSocket, String clientPrivateKeyNameFile) throws Exception {
	    	        HandshakeMessage finishhandshake = new HandshakeMessage();
	    	        finishhandshake.recv(handshakeSocket);
	    	        if (finishhandshake.getParameter("MessageType").equals("Session")) {
	    	            sessionHost = finishhandshake.getParameter("SessionHost");
	    	            sessionPort = Integer.parseInt(finishhandshake.getParameter("SessionPort"));
	    	            PrivateKey clientPrivateKey = HandshakeCrypto.getPrivateKeyFromKeyFile(clientPrivateKeyNameFile);
	    	            
	    	            byte[] decodedSessionKey = Base64.getDecoder().decode(finishhandshake.getParameter("SessionKey"));
	    	            byte[] decodedSessionIV = Base64.getDecoder().decode(finishhandshake.getParameter("SessionIV"));

	    	            sessionKey = HandshakeCrypto.decrypt(decodedSessionKey, clientPrivateKey);
	    	            sessionIV = HandshakeCrypto.decrypt(decodedSessionIV, clientPrivateKey);

	    	            //sessionEncrypter = new SessionEncrypter(decryptedKey, decryptedIV);
	    	           // sessionDecrypter = new SessionDecrypter(decryptedKey, decryptedIV);

	    	            System.out.println("Handshake complete.");
	    	        } else {
	    	            System.out.println("Handshake Error");
	    	            handshakeSocket.close();
	    	        }
	    	    }
	    	 public static byte[] getSessionKey() {
	    		 return sessionKey;
	    	 }
	    	 public static byte[] getSessionIV() {
	    		 return sessionIV;
	    	 }


    	
    	
    
}
