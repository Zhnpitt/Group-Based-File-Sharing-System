/* File worker thread handles the business of uploading, downloading, and removing files for clients with valid tokens */

import java.lang.Thread;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.util.*;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.io.*;

public class FileThread extends Thread {
    private final Socket socket;
    private FileServer my_fs;
    private PrivateKey fileSeverPriKey;
    public PublicKey gsPublicKey;
    private SecretKey sessionKey;
    private SecretKey integrityKey;
    private int seqNumber;

    public FileThread(Socket _socket) {
        socket = _socket;
    }

    public FileThread (Socket _socket, FileServer _fs, PrivateKey p, PublicKey gsPublicKey) {
        socket = _socket;
        my_fs = _fs;
        fileSeverPriKey = p;
        this.gsPublicKey =  gsPublicKey;
    }

    public void run() {
        boolean proceed = true;
        Security.addProvider(new BouncyCastleProvider());
        try {
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            Envelope response = null;

            do {
                Envelope e = (Envelope)input.readObject();
                System.out.println("Request received: " + e.getMessage());

                // Handler to list files that this user is allowed to see
                if(e.getMessage().equals("GetPubKey")) {
                    response = new Envelope("OK");
                    response.addObject(my_fs.getFileServerPubKey());
                    output.writeObject(response);
                } 
                else if (e.getMessage().equals("SessionKeyConfirmation")){
                    if(e.getObjContents().size() < 1) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");
                        if(e.getObjContents().get(0) != null) {
                            SealedObject sealedObject = (SealedObject) e.getObjContents().get(0);
                            String Algorithm = sealedObject.getAlgorithm();
                            Cipher cipher= Cipher.getInstance(Algorithm,"BC");
                            cipher.init(Cipher.DECRYPT_MODE, fileSeverPriKey);
                            KeyChallengePack kCPack = (KeyChallengePack) sealedObject.getObject(cipher);
                            
                            int challenge = kCPack.getChallenge();
                            byte[] challengeByte = ByteBuffer.allocate(4).putInt(challenge).array();
                            sessionKey = kCPack.getSecretKey();
                            integrityKey = kCPack.getIntegrityKey();

                            seqNumber = getNonce();

                            response = new Envelope("OK");
                            response.addObject(challenge);
                            output.writeObject(encryptBySessionKey(response));
                        }
                    }

                } else if (e.getMessage().equals("EncryptMsg")) { 
                    e = decryptBySessionKey(e);
                    System.out.println("EncryptMsg: " + e.getMessage());

                    if(e.getMessage().equals("LFILES")) {
                    
                        if(e.getObjContents().size() < 1) {
                            response = new Envelope("FAIL-BADCONTENTS");
                        } else {
                            if(e.getObjContents().get(0) == null) {
                                response = new Envelope("FAIL-BADToken");
                            } else {
                                Token myToken = (Token)e.getObjContents().get(0); 

                                if (authToken(myToken)) {
                                    List<String> allowedGroups = myToken.getGroups(); // get requester name and group it has access to.
                                    // ArrayList<ShareFile> sf = new ArrayList<>(); 
                                    List<String> outPut = new ArrayList<>();
    
                                    for (String group: allowedGroups){ 
                                        for(ShareFile file : FileServer.fileList.getFiles()) { // shareFile have groupName, owner and path
                                            if (group.equals(file.getGroup())){
                                                outPut.add(file.getPath());
                                            }
                                        }
                                    }
                                    
                                    response = new Envelope("OK");
                                    response.addObject(outPut);
                                   
                                }
                                
                            }
                        }
                        output.writeObject(encryptBySessionKey(response));
                    }
                    else if(e.getMessage().equals("UPLOADF")) {
    
                        if(e.getObjContents().size() < 3) {
                            response = new Envelope("FAIL-BADCONTENTS");
                        } else {
                            if(e.getObjContents().get(0) == null) {
                                response = new Envelope("FAIL-BADPATH");
                            }
                            if(e.getObjContents().get(1) == null) {
                                response = new Envelope("FAIL-BADGROUP");
                            }
                            if(e.getObjContents().get(2) == null) {
                                response = new Envelope("FAIL-BADTOKEN");
                            } else {
                                String remotePath = (String)e.getObjContents().get(0);
                                String group = (String)e.getObjContents().get(1);
                                Token yourToken = (Token)e.getObjContents().get(2); //Extract token
                                int keyVersion = (Integer) e.getObjContents().get(3);
                                byte[] IVarray = (byte[]) e.getObjContents().get(4);

                                if (authToken(yourToken)) {

                                    if (FileServer.fileList.checkFile(remotePath)) {
                                        System.out.printf("Error: file already exists at %s\n", remotePath);
                                        response = new Envelope("FAIL-FILEEXISTS"); //Success
                                    } else if (!yourToken.getGroups().contains(group)) {
                                        System.out.printf("Error: user missing valid token for group %s\n", group);
                                        response = new Envelope("FAIL-UNAUTHORIZED"); //Success
                                    } else  {
                                        File file = new File("shared_files/"+remotePath.replace('/', '_'));
                                        file.createNewFile();
                                        
                                        FileOutputStream fos = new FileOutputStream(file);
                                        System.out.printf("Successfully created file %s\n", remotePath.replace('/', '_'));
        
                                        response = new Envelope("READY"); //Success
                                        output.writeObject(encryptBySessionKey(response));
        
                                        e =  decryptBySessionKey((Envelope)input.readObject());

                                        while (e.getMessage().compareTo("CHUNK")==0) {
                                            fos.write((byte[])e.getObjContents().get(0), 0, (Integer)e.getObjContents().get(1));
                                            response = new Envelope("READY"); //Success
                                            output.writeObject(encryptBySessionKey(response));
                                            e = decryptBySessionKey((Envelope)input.readObject());
                                        }
        
                                        if(e.getMessage().compareTo("EOF")==0) {
                                            System.out.printf("Transfer successful file %s\n", remotePath);
                                            FileServer.fileList.addFile(yourToken.getSubject(), group, remotePath, keyVersion,IVarray);
                                            response = new Envelope("OK"); //Success
                                        } else {
                                            System.out.printf("Error reading file %s from client\n", remotePath);
                                            response = new Envelope("ERROR-TRANSFER"); //Success
                                        }
                                        fos.close();
                                    }

                                }
                                
                            }
                        }
                        output.writeObject(encryptBySessionKey(response));
                    } else if (e.getMessage().compareTo("DOWNLOADF")==0) {
    
                        String remotePath = (String)e.getObjContents().get(0);
                        Token t = (Token)e.getObjContents().get(1);

                        ShareFile sf = FileServer.fileList.getFile(remotePath);

                        if (authToken(t)) {
                            if (sf == null) {
                                System.out.printf("Error: File %s doesn't exist\n", remotePath);
                                e = new Envelope("ERROR_FILEMISSING");
                                output.writeObject(encryptBySessionKey(e));
        
                            } else if (!t.getGroups().contains(sf.getGroup())) {
                                System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                                e = new Envelope("ERROR_PERMISSION");
                                output.writeObject(encryptBySessionKey(e));
                                
                            } else {
        
                                try {
                                    File f = new File("shared_files/"+remotePath.replace('/', '_'));
                                    if (!f.exists()) {
                                        System.out.printf("Error file %s missing from disk\n", "_"+remotePath.replace('/', '_'));
                                        e = new Envelope("ERROR_NOTONDISK");
                                        output.writeObject(encryptBySessionKey(e));
        
                                    } else {

                                        e = new Envelope("KeyVersionAndIVarray");
                                        e.addObject(sf.getKeyVersion());
                                        e.addObject(sf.getKeyIVarray());
                                        output.writeObject(encryptBySessionKey(e));

                                        e = decryptBySessionKey((Envelope)input.readObject());

										if (!e.getMessage().equals("DOWNLOADF")) {
											System.out.printf("Key Version send/rec'v error: %s\n", e.getMessage());
											break;
										}
                                        
                                        FileInputStream fis = new FileInputStream(f);
        
                                        do {
                                            byte[] buf = new byte[4096];
                                            if (e.getMessage().compareTo("DOWNLOADF")!=0) {
                                                System.out.printf("Server error: %s\n", e.getMessage());
                                                break;
                                            }
                                            e = new Envelope("CHUNK");
                                            int n = fis.read(buf); //can throw an IOException
                                            if (n > 0) {
                                                System.out.printf(".");
                                            } else if (n < 0) {
                                                System.out.println("Read error");
        
                                            }
        
        
                                            e.addObject(buf);
                                            e.addObject(Integer.valueOf(n));
                                            
                                            output.writeObject(encryptBySessionKey(e));
        
                                            e = decryptBySessionKey((Envelope)input.readObject());
        
        
                                        } while (fis.available()>0);
        
                                        //If server indicates success, return the member list
                                        if(e.getMessage().compareTo("DOWNLOADF")==0) {
        
                                            e = new Envelope("EOF");
                                            output.writeObject(encryptBySessionKey(e));
        
                                            e = decryptBySessionKey((Envelope)input.readObject());
                                            if(e.getMessage().compareTo("OK")==0) {
                                                System.out.printf("File data upload successful\n");
                                            } else {
        
                                                System.out.printf("DOWNLOADF failed: %s\n", e.getMessage());
        
                                            }
        
                                        } else {
        
                                            System.out.printf("DOWNLOADF failed: %s\n", e.getMessage());
        
                                        }
                                    }
                                } catch(Exception e1) {
                                    System.err.println("Error: " + e.getMessage());
                                    e1.printStackTrace(System.err);
        
                                }
                            }

                        }else {
							e = new Envelope("FAIL-BADTOKENAUTH");
							output.writeObject(encryptBySessionKey(e));
						}
                        
                    } else if (e.getMessage().compareTo("DELETEF")==0) {
                        // ArrayList<String> l = new ArrayList<String>();
                         //ArrayList<ShareFile> s = new ArrayList<ShareFile>();
                        String remotePath = (String)e.getObjContents().get(0);
                        Token t = (Token)e.getObjContents().get(1);

                        ShareFile sf = FileServer.fileList.getFile(remotePath);// without'/', its fileName. with'/',it's path.
                        
                        if (authToken(t)) {
                            if (sf == null) {
                                System.out.printf("Error: File %s doesn't exist\n", remotePath);
                                e = new Envelope("ERROR_DOESNTEXIST");
                            } else if (!t.getGroups().contains(sf.getGroup())) {
                                System.out.printf("Error user %s doesn't have permission\n", t.getSubject());
                                e = new Envelope("ERROR_PERMISSION");
                            } else {
        
                                try {
        
                                    File f = new File("shared_files/"+remotePath.replace('/', '_'));
        
                                    if (!f.exists()) {
                                        System.out.printf("Error file %s missing from disk\n", remotePath.replace('/', '_'));
                                        e = new Envelope("ERROR_FILEMISSING");
                                    } else if (f.delete()) {
                                        System.out.printf("File %s deleted from disk\n", remotePath.replace('/', '_'));
                                        FileServer.fileList.removeFile(remotePath);
                                        e = new Envelope("OK");
                                    } else {
                                        System.out.printf("Error deleting file %s from disk\n", remotePath.replace('/', '_'));
                                        e = new Envelope("ERROR_DELETE");
                                    }
        
        
                                } catch(Exception e1) {
                                    System.err.println("Error: " + e1.getMessage());
                                    e1.printStackTrace(System.err);
                                    e = new Envelope(e1.getMessage());
                                }
                            }

                        }
                        
                        output.writeObject(encryptBySessionKey(e));
                    }

                } else if(e.getMessage().equals("DISCONNECT")) {
                    socket.close();
                    proceed = false;
                } else {  // Server does not understand client request
					response = new Envelope("FAIL");
					output.writeObject(encryptBySessionKey(response));
					proceed = false;
				}
            } while(proceed);
        } 
        catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private Integer getNonce() {
       SecureRandom random = new SecureRandom();
       int num = random.nextInt(200000000);
       return num;
    }

    private Envelope decryptBySessionKey(Envelope message) {
        try{
            
            SealedObject sealedObject = (SealedObject) message.getObjContents().get(0);
            byte[] IVarray = (byte[]) message.getObjContents().get(1);
            byte[] hmac = (byte[]) message.getObjContents().get(2);

            String algorithm = sealedObject.getAlgorithm();
            Cipher cipherDecrypt = Cipher.getInstance(algorithm,"BC");
            cipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));

            // check mac 
            Mac mac = Mac.getInstance("HmacSHA1","BC");
            mac.init(integrityKey);
            mac.update(objectToBytes(sealedObject));

            if (!Arrays.equals(hmac, mac.doFinal())) {
                System.out.println("Hmac integrity damaged.");
                return new Envelope("HmacDamaged");
            }

            Envelope intermidiate = (Envelope) sealedObject.getObject(cipherDecrypt);

            if (seqNumber + 1 == (Integer) intermidiate.getObjContents().get(0)) {
                seqNumber += 2;
                return (Envelope) intermidiate.getObjContents().get(1);
            } else {
                System.out.println("Sequence number integrity damaged.");
                return new Envelope("SeqNumDamaged");
            }

        }catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
        }
        return null;       
    }
    
    private Envelope encryptBySessionKey(Envelope message) {
        try {
            Envelope seqMsg = new Envelope("seqMsg");
            seqMsg.addObject(seqNumber);
            seqMsg.addObject(message);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
            SecureRandom IV = new SecureRandom();
            byte[] IVarray = new byte[16];
            IV.nextBytes(IVarray);
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
            SealedObject sealedObject = new SealedObject(seqMsg, cipher);
            
            // do Hmac
            Mac hmac = Mac.getInstance("HmacSHA1","BC");
            hmac.init(integrityKey);
            hmac.update(objectToBytes(sealedObject));

            Envelope encryptMsg = new Envelope("Encrypt");
            encryptMsg.addObject(sealedObject);
            encryptMsg.addObject(IVarray);
            encryptMsg.addObject(hmac.doFinal());
            return encryptMsg;
            
        } catch (Exception e) {
            // TODO Auto-generated catch block
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
        return null;
    }


    private byte[] objectToBytes(Object sealedObject) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ObjectOutputStream oos = new ObjectOutputStream(baos);
        oos.writeObject(sealedObject);
        oos.flush();
        oos.close();
        baos.close();
        return baos.toByteArray();
    }

    public boolean authToken (Token token) {
        try{
            Signature signedToken = Signature.getInstance("SHA256withRSA","BC");
            signedToken.initVerify(gsPublicKey);
            signedToken.update(token.convertTokentoString());

            Date timeStamp= token.getDate();
            Calendar date =Calendar.getInstance();
            long currTimeMS=date.getTimeInMillis();
            Date currTime=new Date(currTimeMS);
            boolean flag=false;
            if(currTime.compareTo(timeStamp)<0){
                flag=true;
            }
            if (signedToken.verify(token.getSignedT()) && flag) {

            } else {
                return false;
            }

            // if(token.getFSName().equals(socket.getLocalAddress().getHostName())) {

            // }else {
            //     System.out.println("FS add failed");
			//     return false;
            // }

            // if(token.getFSPort() == socket.getLocalPort()) {

            // }else {
            //     System.out.println("FS port failed");
			//     return false;
            // }
            // return true;

            // System.out.println("FS pubkey : "+ token.getServerKey());
            // System.out.println("  "+ my_fs.getFileServerPubKey().toString());

            if(token.getServerKey().equals(my_fs.getFileServerPubKey().toString())) {

            }else {
                System.out.println("FS add failed");
			    return false;
            }
            return true;
        }
        catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
    }


}
