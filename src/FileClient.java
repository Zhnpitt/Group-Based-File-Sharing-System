/* FileClient provides all the client functionality regarding the file server */

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.security.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class FileClient extends Client implements FileClientInterface {

    // public PublicKey getPublicKeyFromFS () {


    // }
    private SecretKey sessionKey;
    private SecretKey integrityKey;
    private int seqNumber;

    public boolean sendSessionkeyToFS() {
        Security.addProvider(new BouncyCastleProvider());

        try{
            Cipher sessionKeyCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC"); // ECB for short ramdom number.
            
            sessionKey = getSessionKey();
            int challenge = getNonce();
            integrityKey = getIntegrityKey();

            KeyChallengePack sessChallengePack = new KeyChallengePack(challenge, sessionKey,integrityKey);

            Cipher msgCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
            msgCipher.init(Cipher.ENCRYPT_MODE, getPubKey()); 
            SealedObject cipherText = new SealedObject(sessChallengePack, msgCipher); // encrypt with cipher.
            
            Envelope message = null, response = null;
            message = new Envelope("SessionKeyConfirmation");
            message.addObject(cipherText);
            output.writeObject(message);

            // //Get the response from the server
            response = (Envelope)input.readObject();
            if(response.getMessage().equals("Encrypt")) {

                SealedObject sealedObject = (SealedObject)response.getObjContents().get(0);
                byte[] IVarray = (byte[]) response.getObjContents().get(1);
                byte[] hmac = (byte[]) response.getObjContents().get(2);

                String algorithm = sealedObject.getAlgorithm();
                Cipher c = Cipher.getInstance(algorithm);
                c.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
                Envelope seqMsg = (Envelope) sealedObject.getObject(c);
                Envelope chall = (Envelope) seqMsg.getObjContents().get(1);
                
                // check hmac
                Mac checkMac = Mac.getInstance("HmacSHA1","BC");
                checkMac.init(integrityKey);
                checkMac.update(objectToBytes(sealedObject));

                if (!Arrays.equals(hmac, checkMac.doFinal())) {
                    System.out.println("Hmac not matched. Group Server not authenticated.");
                }

                if (challenge == (Integer) chall.getObjContents().get(0)) {
                    seqNumber = (Integer) seqMsg.getObjContents().get(0) + 1;
                    System.out.println("Session key challenge matched. Group Server Authenticated.");
                    return true;
                } else {
                    System.out.println("Session key challenge & Hmac integrity failed.");
                }

            }

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);   
        }
        return false;
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

    private SecretKey getIntegrityKey() {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA1","BC");
            keyGen.init(128);
            integrityKey = keyGen.generateKey();
            return integrityKey;
        } catch (NoSuchAlgorithmException e) {
            
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private int getNonce() {
        SecureRandom random = new SecureRandom();
        int num = random.nextInt(1000); //  range ?
        return num;
    }

    //here is a change 

    private SecretKey getSessionKey() {
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES","BC");
            keyGen.init(128);
            sessionKey = keyGen.generateKey();
            return sessionKey;
        } catch (NoSuchAlgorithmException e) {
            
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;

    }

    public PublicKey getPubKey() {
        try {
            PublicKey pubKey = null;
            Envelope message = null, response = null;

            //Tell the server to return a token.
            message = new Envelope("GetPubKey");
            output.writeObject(message);

            //Get the response from the server
            response = (Envelope)input.readObject();

            //Successful response
            if(response.getMessage().equals("OK")) {
                //If there is a public key in the Envelope, return it
                ArrayList<Object> temp = response.getObjContents();

                if(temp.size() == 1) {
                    pubKey = (PublicKey)temp.get(0);
                    // System.out.println("user has group server public key"); // test
                    return pubKey;
                }
            }
            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }

    }

    public Envelope encryMsg(Envelope message) {
        try{
            Envelope seqMsg = new Envelope("seqMsg");
            seqMsg.addObject(seqNumber);
            seqMsg.addObject(message);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
            byte[] IVarray = getIV();
            cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));
            SealedObject cipherText = new SealedObject(seqMsg, cipher);

            // do hmac
            Mac hmac = Mac.getInstance("HmacSHA1","BC");
            hmac.init(integrityKey);
            hmac.update(objectToBytes(cipherText));
    
            Envelope cipherMsg  = null, response = null;
            cipherMsg = new Envelope("EncryptMsg");
            cipherMsg.addObject(cipherText);
            cipherMsg.addObject(IVarray);
            cipherMsg.addObject(hmac.doFinal());
            output.writeObject(cipherMsg);
    
            response = (Envelope) input.readObject();
            if (response.getMessage().equals("Encrypt")) {
                SealedObject sealedCipher = (SealedObject) response.getObjContents().get(0);
                IVarray = (byte[]) response.getObjContents().get(1);
                byte[] hhmac = (byte[]) response.getObjContents().get(2);
                
                String algorithm = sealedCipher.getAlgorithm();
                Cipher cipher2 = Cipher.getInstance(algorithm,"BC");
                cipher2.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));

                // check mac
                Mac mac = Mac.getInstance("HmacSHA1","BC");
                mac.init(integrityKey);
                mac.update(objectToBytes(sealedCipher));

                if (!Arrays.equals(hhmac, mac.doFinal())) {
                    System.out.println("Hmac integrity damaged");
                    return new Envelope("HmacDamaged");
                }
                Envelope intermediate = (Envelope) sealedCipher.getObject(cipher2);
                if (seqNumber+1 == (Integer) intermediate.getObjContents().get(0)) {
                    seqNumber+=2;
                    return (Envelope) intermediate.getObjContents().get(1);
                } else {
                    System.out.println("Sequence number integrity damaged.");
                    return new Envelope("SeqNumDamaged");
                }
            }

        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        return null;
    }

    public boolean checkMsg(String s) {
        if (s.equals("OK")) {
            return true;
        } else if (s.equals("HmacDamaged")) {
            System.out.println("Hmac integrity damaged");
            return false;
        } else if (s.equals(("SeqNumDamaged"))) {
            System.out.println("Sequence number integrity damaged");
            return false;
        }
        else {
            return false;
        }
    }

    public static  byte[] getIV() {
        SecureRandom IV = new SecureRandom();
        byte[] IVarray = new byte[16];
        //System.out.println(Arrays.toString(IVarray));
        IV.nextBytes(IVarray);
        //System.out.println(Arrays.toString(IVarray));
        return IVarray;
    }


    public boolean delete(String filename, UserToken token) {
        String remotePath;
        if (filename.charAt(0)=='/') {
            remotePath = filename.substring(1);
        } else {
            remotePath = filename;
        }
        Envelope env = new Envelope("DELETEF"); //Success

        env.addObject(remotePath);
        env.addObject(token);

        try {
            
            env = encryMsg(env);

            if (checkMsg(env.getMessage())) {
                System.out.printf("File %s deleted successfully\n", filename);
            } else {
                System.out.printf("Error deleting file %s (%s)\n", filename, env.getMessage());
                return false;
            }
        } catch (Exception e1) {
            e1.printStackTrace();
        } 

        return true;
    }

    public boolean download(String sourceFile, String destFile, UserToken token, ArrayList<SecretKey> keyLists) {
        if (sourceFile.charAt(0)=='/') {
            sourceFile = sourceFile.substring(1);
        }

        File file = new File(destFile);
        try {


            if (!file.exists()) {
                file.createNewFile();
                FileOutputStream fos = new FileOutputStream(file);
                int keyVersion;
                byte[] IVarray;

                Envelope env = new Envelope("DOWNLOADF"); //Success

                env.addObject(sourceFile);
                env.addObject(token);

                env = encryMsg(env);

                if (env.getMessage().equals("KeyVersionAndIVarray")) {
					keyVersion = (Integer)env.getObjContents().get(0);
                    IVarray = (byte[]) env.getObjContents().get(1); // IVarray for encrypting file 

                    env = encryMsg(new Envelope("DOWNLOADF"));
				}
				else {
					System.out.printf("Error retrieving file key version and IVarray for %s (%s)\n", sourceFile, env.getMessage());
					file.delete();
					return false;
				}

                Cipher CipherdecryptBuf = Cipher.getInstance("AES/CTR/NoPadding", "BC");


                while (env.getMessage().compareTo("CHUNK")==0) {
                    CipherdecryptBuf.init(Cipher.DECRYPT_MODE, keyLists.get(keyVersion), new IvParameterSpec(IVarray));
                    byte[] decryptBuf = CipherdecryptBuf.doFinal((byte[]) env.getObjContents().get(0));

                    fos.write(decryptBuf, 0, (Integer)env.getObjContents().get(1));
                    System.out.printf(".");
                    env = new Envelope("DOWNLOADF"); //Success
                    
                    env = encryMsg(env);
                }
                fos.close();

                if(env.getMessage().compareTo("EOF")==0) {
                    fos.close();
                    System.out.printf("\nTransfer successful file %s\n", sourceFile);
                    env = new Envelope("OK"); //Success
                    // output.writeObject(env);

                    try {
                        Envelope seqMsg = new Envelope("seqMsg");
                        seqMsg.addObject(seqNumber);
                        seqMsg.addObject(env);

                        // Encrypt original Envelope
                        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding","BC");
                        byte[] IVarray2 = getIV();
                        cipher.init(Cipher.ENCRYPT_MODE, sessionKey, new IvParameterSpec(IVarray2));
						SealedObject outCipher = new SealedObject(seqMsg, cipher);

                        // do hamc 
                        Mac mac = Mac.getInstance("HmacSHA1","BC");
                        mac.init(integrityKey);
                        mac.update(objectToBytes(outCipher));


						// Create new Envelope with encrypted data and IV
						Envelope cipherMsg = new Envelope("Encrypt");
						// Envelope encResponse = null;

						cipherMsg.addObject(outCipher);
						cipherMsg.addObject(IVarray2);
                        cipherMsg.addObject(mac.doFinal());

						output.writeObject(cipherMsg);
                        // update sequence number 
                        seqNumber += 2;
					}
					catch(Exception e) {
						System.out.println("Error: " + e);
						e.printStackTrace();
					}


                } else {
                    System.out.printf("Error reading file %s (%s)\n", sourceFile, env.getMessage());
                    file.delete();
                    return false;
                }
            }

            else {
                System.out.printf("Error couldn't create file %s\n", destFile);
                return false;
            }


        } catch (IOException e1) {

            System.out.printf("Error couldn't create file %s\n", destFile);
            return false;


        } catch (Exception e1) {
            e1.printStackTrace();
        }
        return true;
    }

    @SuppressWarnings("unchecked")
    public List<String> listFiles(UserToken token) {
        try {
            Envelope message = null, e = null;
            //Tell the server to return the member list
            message = new Envelope("LFILES");
            message.addObject(token); //Add requester's token

            e = encryMsg(message);

            //If server indicates success, return the member list
            if(checkMsg(e.getMessage())) {
                return (List<String>)e.getObjContents().get(0); //This cast creates compiler warnings. Sorry.

            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean upload(String sourceFile, String destFile, String group, UserToken token, ArrayList<SecretKey> keyLists) {

        // if (destFile.charAt(0)!='/') {
        //     //destFile = " " + destFile;
        // }

        try {

            byte[] IVarray = getIV();

            Envelope message = null, env = null;
            //Tell the server to return the member list
            message = new Envelope("UPLOADF");
            message.addObject(destFile); 
            message.addObject(group);
            message.addObject(token); // Add requester's token
            message.addObject(keyLists.size()-1);
            message.addObject((IVarray));

            FileInputStream fis = new FileInputStream(sourceFile);

            env = encryMsg(message);

            //If server indicates success, return the member list
            if(env.getMessage().equals("READY")) {
                System.out.printf("Meta data upload successful\n");

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }

            Cipher byteCipher = Cipher.getInstance("AES/CTR/NoPadding","BC");
            
            int version = keyLists.size() -1;

            do {
                byte[] buf = new byte[4096];
                if (env.getMessage().compareTo("READY")!=0) {
                    System.out.printf("Server error: %s\n", env.getMessage());
                    return false;
                }
                message = new Envelope("CHUNK");
                int n = fis.read(buf); //can throw an IOException
                if (n > 0) {
                    System.out.printf(".");
                } else if (n < 0) {
                    System.out.println("Read error");
                    return false;
                }

                byteCipher.init(Cipher.ENCRYPT_MODE, keyLists.get(version), new IvParameterSpec(IVarray));
                byte[] encryptedBuf = byteCipher.doFinal(buf);

                message.addObject(encryptedBuf);
                message.addObject(Integer.valueOf(n));

                env = encryMsg(message);

            } while (fis.available()>0);
            

            //If server indicates success, return the member list
            if(env.getMessage().compareTo("READY")==0) {

                message = new Envelope("EOF");
                env = encryMsg(message);
                
                if (checkMsg(env.getMessage())) {
                    System.out.printf("\nFile data upload successful\n");
                } else {

                    System.out.printf("\nUpload failed: %s\n", env.getMessage());
                    return false;
                }

            } else {

                System.out.printf("Upload failed: %s\n", env.getMessage());
                return false;
            }
        
        } catch(Exception e1) {
            System.err.println("Error: " + e1.getMessage());
            e1.printStackTrace(System.err);
            return false;
        }
        return true;
    }

}

