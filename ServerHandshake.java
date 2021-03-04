/**
 * Server side of the handshake.
 */

import java.net.Socket;
import java.security.PublicKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.ServerSocket;

public class ServerHandshake {
    /*
     * The parameters below should be learned by the server
     * through the handshake protocol. 
     */
	//private static ForwardServer arguments;
	//private ServerSocket listenSocket;

    //private static SessionEncrypter sessionEncrypter;
    //private static SessionDecrypter sessionDecrypter;
    public static byte[] sessionKey;
    public static byte[] sessionIV;
    public static X509Certificate clientCert;
    /* Session host/port, and the corresponding ServerSocket  */
    public static ServerSocket sessionSocket;
    public static String sessionHost;
    public static int sessionPort;    

    /* The final destination -- simulate handshake with constants */
    public static String targetHost = "localhost";
    public static int targetPort = 6789;

    /* Security parameters key/iv should also go here. Fill in! */

    /**
     * Run server handshake protocol on a handshake socket. 
     * Here, we simulate the handshake by just creating a new socket
     * with a preassigned port number for the session.
     * @throws Exception 
     */ 
    public ServerHandshake(Socket handshakeSocket) throws Exception {
        sessionSocket = new ServerSocket(12345);
        sessionHost = sessionSocket.getInetAddress().getHostName();
        sessionPort = sessionSocket.getLocalPort();
        //Handshake handshake = new Handshake();
        serverVerify(ForwardServer.arguments.get("cacert"), handshakeSocket);
        serverHello(ForwardServer.arguments.get("usercert"), handshakeSocket);
        
        //listenSocket = new ServerSocket(0, 10, InetAddress.getLocalHost());
        sessionMessage(sessionHost, sessionPort, handshakeSocket);
        handshakeSocket.close();
        
       System.out.println("Handshake is done.");
       // sessionDecrypter = handshake.getSessionDecrypter();
        //sessionEncrypter = handshake.getSessionEncrypter();

    }
    private void serverVerify(String CAcert, Socket handshakeSocket) throws Exception {
        HandshakeMessage fromClientHello = new HandshakeMessage();
        fromClientHello.recv(handshakeSocket);
        if(fromClientHello.getParameter("MessageType").equals("ClientHello")){
         /*   String clientCertString = fromClientHello.getParameter("Certificate");
            byte[] clientCertBytes = Base64.getDecoder().decode(clientCertString);
            InputStream clientCertIn = new ByteArrayInputStream(clientCertBytes);
            clientCert = (X509Certificate) cf.generateCertificate(clientCertIn);

            InputStream CACertIn = new FileInputStream(cacert);
            CACert = (X509Certificate) cf.generateCertificate(CACertIn);

            VerifyCertificate.Verifycertificate(CACert,clientCert);
*/
        	String clientCertString = fromClientHello.getParameter("Certificate");
        	 PublicKey CAkey = VerifyCertificate.getCertification(CAcert).getPublicKey();
             clientCert = VerifyCertificate.createCertification(clientCertString);
             VerifyCertificate.Verifycertificate(VerifyCertificate.getCertification(CAcert), clientCert, CAkey);
            System.out.println("Client certificate is validated.");
        }
        else{
            System.out.println("Server Verify Client certificate Error");
            handshakeSocket.close();
        }
    }
    private void serverHello(String usercert,Socket handshakeSocket) throws CertificateException, Exception {
	    HandshakeMessage ServerHello = new HandshakeMessage();
        //InputStream serverCertIn = new FileInputStream(usercert);
        //serverCert = (X509Certificate) cf.generateCertificate(serverCertIn);
        // serverCertNobase64 = VerifyCertificate.getCertification(usercert);
        //String serverCertString = Base64.getEncoder().encodeToString(VerifyCertificate.getCertification(usercert);
        ServerHello.putParameter("MessageType", "ServerHello");
        ServerHello.putParameter("Certificate", Base64.getEncoder().encodeToString(VerifyCertificate.getCertification(usercert).getEncoded()));
        ServerHello.send(handshakeSocket);
    }
    private void sessionMessage(String sessionHost, int sessionPort, Socket handshakeSocket) throws Exception {
       
        HandshakeMessage fromForwardMessage = new HandshakeMessage();
        fromForwardMessage.recv(handshakeSocket);
        if(fromForwardMessage.getParameter("MessageType").equals("Forward")) {
            targetHost = fromForwardMessage.getParameter("TargetHost");
            targetPort = Integer.parseInt(fromForwardMessage.getParameter("TargetPort"));
            HandshakeMessage sessionmessage = new HandshakeMessage();
            SessionEncrypter sessionEncrypter = new SessionEncrypter(128);
            //sessionKey = new SessionKey(128);
           // sessionDecrypter = new SessionDecrypter(sessionEncrypter.getKeyBytes(), sessionEncrypter.getIVBytes());
            PublicKey clientPublicKey = clientCert.getPublicKey();
            sessionKey = sessionEncrypter.getKeyBytes();
            sessionIV = sessionEncrypter.getIVBytes();
            
            byte[] encryptedSessionKeyByte = HandshakeCrypto.encrypt(sessionKey, clientPublicKey);
            //byte[] encryptedSessionKeyByte = HandshakeCrypto.encrypt(sessionKey.getKeyBytes(), clientPublicKey);
            byte[] encryptedIVByte = HandshakeCrypto.encrypt(sessionIV, clientPublicKey);

            String encryptedIV = Base64.getEncoder().encodeToString(encryptedIVByte);
            String encryptedSessionKey = Base64.getEncoder().encodeToString(encryptedSessionKeyByte);

            sessionmessage.putParameter("MessageType", "Session");
            sessionmessage.putParameter("SessionKey", encryptedSessionKey);
            sessionmessage.putParameter("SessionIV", encryptedIV);
            sessionmessage.putParameter("SessionHost", sessionHost);
            sessionmessage.putParameter("SessionPort", Integer.toString(sessionPort));
            sessionmessage.send(handshakeSocket);

        }else{
            System.out.println("Error in Session Step");
            handshakeSocket.close();
        }
    }
        public static byte[] getSessionKey(){
            return sessionKey;
        }

        public static byte[] getSessionIV(){
            return sessionIV;
        }
    
}
