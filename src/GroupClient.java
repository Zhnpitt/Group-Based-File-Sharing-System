/* Implements the GroupClient Interface */

import java.util.ArrayList;
import java.util.List;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.border.EmptyBorder;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.util.*;



public class GroupClient extends Client implements GroupClientInterface {

    private SecretKey sessionKey;
    private SecretKey integrityKey;
    private int seqNumber;
    
    public Boolean sendSessionKeyToGroup(){

        Security.addProvider(new BouncyCastleProvider());
        try {
            // create session key cipher for later use
            Cipher sessionKeyCipher = Cipher.getInstance("AES/ECB/PKCS5Padding", "BC"); // ECB for short ramdom number.

            sessionKey = getSessionKey();
            integrityKey = getIntegrityKey();
            int challenge = getNonce();
            // System.out.println( "challenge is: " + challenge); // test challenge

            KeyChallengePack sessionChallengePack = new KeyChallengePack(challenge, sessionKey, integrityKey); // concatenate session key and challenge.
            // SecretKey test=new SecretKeySpec(keyB, 0,keyB.length,"AES");

            Cipher msgCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding","BC");
            // System.out.println(" ;;;;;"+ getPubKey());
            msgCipher.init(Cipher.ENCRYPT_MODE, getPubKey()); // call getPubKey method to get pubkey from group server.
            SealedObject cipherText = new SealedObject(sessionChallengePack, msgCipher); // encrypt with cipher.
            
            Envelope message = null, response = null;
            //Tell the server to return a token.
            message = new Envelope("SessionKeyConfirmation");
            message.addObject(cipherText);
            output.writeObject(message);

            // //Get the response from the server
            response = (Envelope)input.readObject();

            // //Successful response
            if(response.getMessage().equals("Encrypt")) {
                //If there is a public key in the Envelope, return it
                SealedObject sealedObject = (SealedObject) response.getObjContents().get(0);
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
                if (!Arrays.equals(checkMac.doFinal(),hmac)) {
                    System.out.println("Hmac not matched. Group Server not authenticated.");
                }

                if(challenge == (Integer) chall.getObjContents().get(0)){
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

    public Integer getNonce(){
        SecureRandom random = new SecureRandom();
        int num = random.nextInt(20000); //  range ?
        return num;
    }

    public SecretKey getSessionKey(){
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES","BC");
            keyGen.init(128);
            sessionKey = keyGen.generateKey();
            return sessionKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException ee){
            ee.printStackTrace();
        }
        return null;
    }

    public SecretKey getIntegrityKey(){
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("HmacSHA1","BC");
            keyGen.init(128);
            integrityKey = keyGen.generateKey();
            return integrityKey;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException ee){
            ee.printStackTrace();
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
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

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

            // do Hmac
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

                // check Hmac
                Mac mac = Mac.getInstance("HmacSHA1","BC");
                mac.init(integrityKey);
                mac.update(objectToBytes(sealedCipher));

                if (!Arrays.equals(hhmac,mac.doFinal())){
                    System.out.println("Hmac integrity damaged");
                    return new Envelope("HmacDamaged");
                }

                Envelope intermediate = (Envelope) sealedCipher.getObject(cipher2);
                if (seqNumber + 1 == (Integer) intermediate.getObjContents().get(0)) {
                    seqNumber += 2;
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

    // public static void main(String[] args) {
    //     getIV();
    // }


    public static  byte[] getIV() {
        SecureRandom IV = new SecureRandom();
        byte[] IVarray = new byte[16];
        //System.out.println(Arrays.toString(IVarray));
        IV.nextBytes(IVarray);
        //System.out.println(Arrays.toString(IVarray));
        return IVarray;
    }

    public UserToken getToken(String username, String password) {
        try {
            UserToken token = null;
            Envelope message = null, response = null;
            

            //Tell the server to return a token.

            message = new Envelope("GET");
            message.addObject(username); //Add user name string
            message.addObject(password);

            // output.writeObject(message);

            //Get the response from the server
            response = encryMsg(message);

            //Successful response
            if(checkMsg(response.getMessage() )) {
                //If there is a token in the Envelope, return it
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    token = (UserToken)temp.get(0);
                    return token;
                }
            } else {
                System.out.println("Wrong password!!!");
            }
            return null;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public UserToken getTokenWithFile(UserToken aToken, PublicKey key) {
        try{
            UserToken token = null;
            Envelope message = null, response = null;

            message = new Envelope("GETTG");
            message.addObject(aToken);
            message.addObject(key);

            response = encryMsg(message);

            if (checkMsg(response.getMessage())) {
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if (temp.size() ==1) {
                    token = (UserToken) temp.get(0);
                    return token;
                }
            } else {
                System.out.println("token with file identity failed!!!");
                
            } 
            return null;
        }catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }


    public boolean changePassword(String password, UserToken token){
        Envelope message = null, response = null;
        message = new Envelope("CHANGEPASS");
        message.addObject(password); 
        message.addObject(token);
        response = encryMsg(message);
        if(checkMsg(response.getMessage())){
            System.out.println("Password Changed");
            return true;
            
        }else if(response.getMessage().equals("TOOSHORT")){
            System.out.println("Password needs to be 12 characters long");
            return false;
        }
        System.out.println("Password not changed");

        return false;

    }

    // private byte[] AESEncrypt(SecretKey session,byte[]message) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
    //     cipherAESEncrypt=Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
    //     byte[] result = new byte[message.length];
    //     try {
    //         cipherAESEncrypt.init(cipherAESEncrypt.ENCRYPT_MODE, session);
    //         result=cipherAESEncrypt.doFinal(message);
    //     } catch (Exception e) {
    //         // TODO Auto-generated catch block
    //         e.printStackTrace();
    //     }
    //     return result;
    // }

    // private byte[] AESDecrypt(SecretKey session,byte[]message) throws NoSuchAlgorithmException, NoSuchProviderException, NoSuchPaddingException{
    //     cipherAESDecrypt=Cipher.getInstance("AES/CFB/PKCS5Padding","BC");
    //     byte[] result = new byte[message.length];
    //     try {
    //         cipherAESDecrypt.init(cipherAESEncrypt.DECRYPT_MODE, session);
    //         result=cipherAESDecrypt.doFinal(message);
    //     } catch (Exception e) {
    //         // TODO Auto-generated catch block
    //         e.printStackTrace();
    //     }
    //     return result;
    // }
 
    //token should be the administrator, username should be one which need to be created. 
    public boolean createUser(String username, UserToken token) { 
        try {
            Envelope message = null, response = null;
            //Tell the server to create a user
            message = new Envelope("CUSER");
            message.addObject(username); //Add user name string
            message.addObject(token); //Add the requester's token
            // output.writeObject(message);

            response = encryMsg(message);

            //If server indicates success, return true
            if(checkMsg(response.getMessage())){
                ArrayList<Object> temp = null;
                temp = response.getObjContents();

                if(temp.size() == 1) {
                    String passW = (String)temp.get(0);
                    System.out.println(username + "'s " + "new password is: " + passW);
                    return true;
                }
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteUser(String username, UserToken token) {
        try {
            Envelope message = null, response = null;

            //Tell the server to delete a user
            message = new Envelope("DUSER");
            message.addObject(username); //Add user name
            message.addObject(token);  //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);

            //If server indicates success, return true
            if(checkMsg(response.getMessage()) ){
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean createGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to create a group
            message = new Envelope("CGROUP");
            message.addObject(groupname); //Add the group name string
            message.addObject(token); //Add the requester's token
            // output.writeObject(message);

            response = encryMsg(message);

            //If server indicates success, return true
            if(checkMsg(response.getMessage())) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    public boolean deleteGroup(String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to delete a group
            message = new Envelope("DGROUP");
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);
            //If server indicates success, return true
            if(checkMsg(response.getMessage())) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }

    @SuppressWarnings("unchecked")
    public List<String> listMembers(String group, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("LMEMBERS");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);

            //If server indicates success, return the member list
            if(checkMsg(response.getMessage())) {
                return (List<String>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    }

    public boolean addUserToGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to add a user to the group
            message = new Envelope("AUSERTOGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);
            //If server indicates success, return true
            if(checkMsg(response.getMessage())) {
                return true;
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        return false;
    }

    public boolean deleteUserFromGroup(String username, String groupname, UserToken token) {
        try {
            Envelope message = null, response = null;
            //Tell the server to remove a user from the group
            message = new Envelope("RUSERFROMGROUP");
            message.addObject(username); //Add user name string
            message.addObject(groupname); //Add group name string
            message.addObject(token); //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);
            //If server indicates success, return true
            if(checkMsg(response.getMessage())) {
                return true;
            }

            return false;
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return false;
        }
    }


    public ArrayList<SecretKey> sendKeyArray(String group, UserToken token){
        try {
            Envelope message = null, response = null;
            //Tell the server to return the member list
            message = new Envelope("SENDARRAY");
            message.addObject(group); //Add group name string
            message.addObject(token); //Add requester's token
            // output.writeObject(message);

            response = encryMsg(message);

            //If server indicates success, return the member list
            if(checkMsg(response.getMessage())) {
                return (ArrayList<SecretKey>)response.getObjContents().get(0); //This cast creates compiler warnings. Sorry.
            }

            return null;

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
            return null;
        }
    
    }



}


