/* This thread does all the work. It communicates with the client through Envelopes.
 *
 */
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.lang.Thread;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class GroupThread extends Thread {
    private final Socket socket;
    private GroupServer my_gs;
    private PrivateKey priKey;
    private SecretKey sessionKey;
    private SecretKey integrityKey;
    private int seqNumber;

    public GroupThread(Socket _socket, GroupServer _gs, PrivateKey p) {
        socket = _socket;
        my_gs = _gs;
        priKey = p;
    }

    public void run() {
        boolean proceed = true;
        Security.addProvider(new BouncyCastleProvider());

        try {
            //Announces connection and opens object streams
            System.out.println("*** New connection from " + socket.getInetAddress() + ":" + socket.getPort() + "***");
            final ObjectInputStream input = new ObjectInputStream(socket.getInputStream());
            final ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            
            do {
                Envelope message = (Envelope)input.readObject();
                System.out.println("Request received: " + message.getMessage());
                Envelope response;

                if(message.getMessage().equals("SessionKeyConfirmation")){
                    if(message.getObjContents().size() < 1) {
                        response = new Envelope("FAIL");
                    } else {
                        response = new Envelope("FAIL");
                        if(message.getObjContents().get(0) != null) {

                            SealedObject sealedObject = (SealedObject) message.getObjContents().get(0);
                            String Algorithm = sealedObject.getAlgorithm();
                            Cipher cipher= Cipher.getInstance(Algorithm,"BC");
                            // System.out.println("private key:" + priKey);
                            cipher.init(Cipher.DECRYPT_MODE, priKey);
                            KeyChallengePack kCPack = (KeyChallengePack) sealedObject.getObject(cipher);

                            int challenge = kCPack.getChallenge();
                            byte[] challengeByte = ByteBuffer.allocate(4).putInt(challenge).array();
                            sessionKey = kCPack.getSecretKey();
                            integrityKey = kCPack.getIntegrityKey();
                            
                            // create sequence number
                            seqNumber = my_gs.getNonce();

                            // Cipher sessionCipher = Cipher.getInstance("AES/ECB/PKCS5Padding","BC");
                            // sessionCipher.init(Cipher.ENCRYPT_MODE, sessionKey);
                            response = new Envelope("OK");
                            response.addObject(challenge);
                            output.writeObject(encryptBySessionKey(response));
                        }
                    }
                
                }else if(message.getMessage().equals("GetPubKey")) {
                    response = new Envelope("OK");
                    response.addObject(my_gs.getGroupServerPubKey());
                    output.writeObject(response);

                }else if (message.getMessage().equals("EncryptMsg")) {
                    if (message.getObjContents().size() < 3) {
                        response = new Envelope("FAIL");
                    } else {

                        message = decryptBySessionKey(message);
                        System.out.println("EncryptMsg: " + message.getMessage());

                        if(message.getMessage().equals("GET")) { //Client wants a token
                            String username = (String)message.getObjContents().get(0); //Get the username
                            String password= (String)message.getObjContents().get(1);
                            String checkPass= my_gs.userList.getPassword(username);
                            
                            if(username == null || password == null|| !checkPass.equals(password)) {
                                response = new Envelope("FAIL");
                                response.addObject(null);
                                output.writeObject(encryptBySessionKey(response));
                            } else {
                                UserToken yourToken = createToken(username); //Create a token
                                //Respond to the client. On error, the client will receive a null token
                                response = new Envelope("OK");
                                response.addObject(yourToken);
                                output.writeObject(encryptBySessionKey(response));
                            }
                        }
                        else if (message.getMessage().equals("GETTG")) {
                            Token token = (Token) message.getObjContents().get(0);
                             PublicKey filePubKey = (PublicKey) message.getObjContents().get(1);
                            
                            if(token == null) {
                                response = new Envelope("FAIL");
                                response.addObject(null);
                                output.writeObject((encryptBySessionKey(response)));
                            } else {
                                Token updateToken = createTokenWithFile(token, filePubKey);
                                response = new Envelope("OK");
                                response.addObject(updateToken);
                                output.writeObject(encryptBySessionKey(response));
                            }
                        } else if(message.getMessage().equals("CUSER")) { //Client wants to create a user
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String username = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
                                        
                                        if (authToken(yourToken)) {
                                            if(createUser(username, yourToken)) {
                                                String pass = my_gs.userList.getPassword(username);
                                                response = new Envelope("OK"); //Success
                                                response.addObject(pass);
                                            }
                                        }
                                       
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("DUSER")) { //Client wants to delete a user
        
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String username = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token

                                        if (authToken(yourToken)) {
                                            if(deleteUser(username, yourToken)) {
                                                response = new Envelope("OK"); //Success
                                            }
                                        }
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("CGROUP")) { //Client wants to create a group
                            
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String groupname = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token

                                        if (authToken(yourToken)) {
                                            if(createGroup(groupname, yourToken)) {
                                                response = new Envelope("OK"); //Success
                                            }
                                        }
                                        
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("DGROUP")) { //Client wants to delete a group
                            
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String groupname = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token

                                        if (authToken(yourToken)){
                                            if(deleteGroup(groupname, yourToken)) {
                                                response = new Envelope("OK"); //Success
                                            }
                                        }
                                        
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("LMEMBERS")) { //Client wants a list of members in a group
                            
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                                response.addObject(null);
							    output.writeObject(encryptBySessionKey(response));

                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String groupname = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
                                        
                                        if (authToken(yourToken)){
                                            List<String> list = listMembers(groupname, yourToken); //Create a member list
        
                                            response = new Envelope("OK");
                                            response.addObject(list);
                                            
                                        }
                                        
                                    }
                                }
                            }
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("AUSERTOGROUP")) { //Client wants to add user to a group
                            if(message.getObjContents().size() < 3) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        if (message.getObjContents().get(2)!=null) {
                                            String username = (String)message.getObjContents().get(0); //Extract the username
                                            String groupname = (String)message.getObjContents().get(1);//extract the groupname
                                            Token yourToken = (Token)message.getObjContents().get(2); //Extract the token
    
                                            if (authToken(yourToken)) {
                                                if(addUserToGroup(username, groupname, yourToken)) {
                                                    response = new Envelope("OK"); //Success
                                                }
                                            }
                                            
                                        }
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("RUSERFROMGROUP")) { //Client wants to remove user from a group
                            if(message.getObjContents().size() < 3) {
                                response = new Envelope("FAIL");
                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        if (message.getObjContents().get(2)!=null) {
                                            String username = (String)message.getObjContents().get(0); //Extract the username
                                            String groupname = (String)message.getObjContents().get(1);//extract the groupname
                                            Token yourToken = (Token)message.getObjContents().get(2); //Extract the token

                                            if (authToken(yourToken)){
                                                if(deleteUserFromGroup(username, groupname, yourToken)) {
                                                    response = new Envelope("OK"); //Success
                                                }
                                            }
                                            
                                        }
                                    }
                                }
                            }
        
                            output.writeObject(encryptBySessionKey(response));
                        } else if(message.getMessage().equals("CHANGEPASS")){
                            if(message.getObjContents().size()<2){
                                response = new Envelope("FAIL");
                            }
                            response = new Envelope("FAIL");
                            if(message.getObjContents().get(0) != null) {
                                if(message.getObjContents().get(1) != null) {
                                    String pass=(String)message.getObjContents().get(0);
                                    Token token=(Token)message.getObjContents().get(1);
                                    if(authToken(token)){
                                        if(pass.length()<12){
                                            response = new Envelope("TOOSHORT");
                                            output.writeObject(encryptBySessionKey(response));
                                        }else if(changePassword(pass,token)){
                                            response=new Envelope("OK");
                                        }

                                    }
                                }
                            }
                            output.writeObject(encryptBySessionKey(response));
                            
                        } else if(message.getMessage().equals("SENDARRAY")){
                            if(message.getObjContents().size() < 2) {
                                response = new Envelope("FAIL");
                                response.addObject(null);
							    output.writeObject(encryptBySessionKey(response));

                            } else {
                                response = new Envelope("FAIL");
        
                                if(message.getObjContents().get(0) != null) {
                                    if(message.getObjContents().get(1) != null) {
                                        String groupname = (String)message.getObjContents().get(0); //Extract the username
                                        Token yourToken = (Token)message.getObjContents().get(1); //Extract the token
                                        
                                        if (authToken(yourToken)){
                                            ArrayList<SecretKey> list = sendKArray(groupname, yourToken); //Create a member list
        
                                            response = new Envelope("OK");
                                            response.addObject(list);
                                            
                                        }
                                        
                                    }
                                }
                            }
                            output.writeObject(encryptBySessionKey(response));


                        }else if(message.getMessage().equals("DISCONNECT")) { //Client wants to disconnect
                            socket.close(); //Close the socket
                            proceed = false; //End this communication loop

                        } else {

                       

                            response = new Envelope("FAIL"); //Server does not understand client request
                            output.writeObject(encryptBySessionKey(response));
                        }
                    }
                } 
            } while(proceed);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    private boolean changePassword(String pass, Token token){
        String requester=token.getSubject();
        if(my_gs.userList.checkUser(requester)){
            my_gs.userList.setPassword(requester, pass);
            return true;
        }
        return false;
    }
    private Envelope encryptBySessionKey(Envelope message) {
        try {
            Envelope seqMsg = new Envelope("seqMsg");
            seqMsg.addObject(seqNumber); // sequence number
            seqMsg.addObject(message); // challenge 

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
            return null;
        }
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

    private Envelope decryptBySessionKey(Envelope message) {
        try{
            SealedObject sealedObject = (SealedObject) message.getObjContents().get(0);
            byte[] IVarray = (byte[]) message.getObjContents().get(1);
            byte[] hmac = (byte[]) message.getObjContents().get(2);

            // check Hmac integrity
            Mac mac = Mac.getInstance("HmacSHA1", "BC");
            mac.init(integrityKey);
            mac.update(objectToBytes(sealedObject));

            if (!Arrays.equals(hmac, mac.doFinal())) {
                System.out.println("Hmac integrity damaged.");
                return new Envelope("HmacDamaged");
            } else {
                String algorithm = sealedObject.getAlgorithm();
                Cipher cipherDecrypt = Cipher.getInstance(algorithm,"BC");
                // System.out.print(sessionKey);
                cipherDecrypt.init(Cipher.DECRYPT_MODE, sessionKey, new IvParameterSpec(IVarray));

                Envelope intermediate = (Envelope) sealedObject.getObject(cipherDecrypt);
                if (seqNumber + 1 == (Integer)intermediate.getObjContents().get(0)) {
                    seqNumber += 2; // update sequence number
                    return (Envelope) intermediate.getObjContents().get(1);
                } else {
                    System.out.println("Sequence number integrity damaged.");
                    return new Envelope("SeqNumDamaged");
                }
            }

        }catch (Exception e) {
            System.out.println("Error: " + e);
            e.printStackTrace();
            return null;
        }       
    }

    private boolean deleteUserFromGroup(String username, String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();
        // check if the userToken(Admin) exits
        if (my_gs.userList.checkUser(requester)) {
            // check if the user(normal) exits
            if (my_gs.userList.checkUser(username)) {
                // check if the groupname exits
                if (my_gs.groupList.checkGroup(groupname)) {
                    boolean flag = false;
                    List<String> owingGroup = my_gs.userList.getUserOwnership(requester);
                    for (String g: owingGroup) {
                        if (g.equals(groupname)) {
                            flag = true;
                        break;
                        }
                    }
                    // if the user is not the owner of the group, cannot list members.
                    if (!flag) {
                        return false;
                    }
                    my_gs.groupList.removeMember(groupname, username);
                    my_gs.userList.removeGroup(username, groupname);
                    my_gs.groupList.addNewKey(groupname);

                    return true;
                } else {
                    return false;
                }
            } else {
                return false;
            }
        }else  {
            return false;
        }
    }

    private boolean addUserToGroup(String username, String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();
        // check if the userToken(Admin) exits
        if (my_gs.userList.checkUser(requester)){
            // check if groupname exits
            if(my_gs.groupList.checkGroup(groupname)) {
                if (my_gs.userList.checkUser(username)) {
                    if (my_gs.groupList.getGroupUsers(groupname).contains(username)){
                        System.out.println("user is already in group");
                        return false;
                    } else{
                        boolean flag = false;
                    List<String> owingGroup = my_gs.userList.getUserOwnership(requester);
                    for (String g: owingGroup) {
                        if (g.equals(groupname)) {
                            flag = true;
                        break;
                        }
                    }
                // if the user is not the owner of the group, cannot list members.
                    if (!flag) {
                        return false;
                    }
                    my_gs.groupList.addMember(groupname, username);
                    my_gs.userList.addGroup(username, groupname);
                    return true;


                    }
                    
                } else {
                    System.out.println("user doesnot exists  1111");
                    return false;
                }
        

            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
                
            } else {
                return false;
            }
        }else {
            return false;
        }
        
    }
    private ArrayList<SecretKey> sendKArray(String group, UserToken token){
        ArrayList<SecretKey> arr = new ArrayList<SecretKey>();
        String requester = token.getSubject();

        if (my_gs.userList.checkUser(requester)) {
            // check if this groupname exits 
            if (my_gs.groupList.checkGroup(group)) {
                boolean flag = false;
                List<String> owingGroup = my_gs.userList.getUserGroups(requester);
                for (String g: owingGroup) {
                    if (g.equals(group)) {
                        flag = true;
                        break;
                    }
                }
                // if the user is not the owner of the group, cannot list members.
                if (!flag) {
                    return arr;
                } else {
                    return my_gs.groupList.getGKeys(group);
                }
            }else {
                return arr;
            }        
        } else {
            return arr;
        }
    }

    private List<String> listMembers(String groupName, UserToken yourToken) {
        List<String> result = new ArrayList<>();
        String requester = yourToken.getSubject();



        

        // check if the user exits.
        if (my_gs.userList.checkUser(requester)) {
            // check if this groupname exits 
            if (my_gs.groupList.checkGroup(groupName)) {
                boolean flag = false;
                List<String> owingGroup = my_gs.userList.getUserOwnership(requester);
                for (String g: owingGroup) {
                    if (g.equals(groupName)) {
                        flag = true;
                        break;
                    }
                }
                // if the user is not the owner of the group, cannot list members.
                if (!flag) {
                    return result;
                } else {
                    return my_gs.groupList.getGroupUsers(groupName);
                }
            }else {
                return result;
            }        
        } else {
            return result;
        }
    
    }

    private boolean deleteGroup(String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();
        // if user exists
        if (my_gs.userList.checkUser(requester)){
            // if this groupname exits
            if (my_gs.groupList.checkGroup(groupname)) {
                // admin group cannot be deleted
                if(groupname.equals("ADMIN")) {
                    return false;
                }
                // check if the user is the owner of the group
                Boolean flag = false; 
                List<String> owningGroup = my_gs.userList.getUserOwnership(requester);
                for(String g: owningGroup) {
                    if (groupname.equals(g)) {
                        flag = true;
                        break;
                    }
                }
                if (!flag) {
                    return false;
                } 
                // remove all the users in this group from userList
                List<String> userList = my_gs.groupList.getGroupUsers(groupname);
                for (String user: userList){
                    my_gs.userList.removeGroup(user, groupname);
                }
                // remove all the users in this group from ownership 
                List<String> ownerList = my_gs.groupList.getGroupOwnership(groupname);
                for (String owner: ownerList) {
                    my_gs.userList.removeOwnership(owner, groupname);
                }
                // delete the group.
                my_gs.groupList.deleteGroup(groupname);
                return true;     
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    private boolean createGroup(String groupname, UserToken yourToken) {
        String requester = yourToken.getSubject();

        // if user exists
        if (my_gs.userList.checkUser(requester)) {
            // if this groupName exists
            if (!my_gs.groupList.checkGroup(groupname)){
                // for groupList object, it adds this specified user and his ownership
                my_gs.groupList.addGroup(groupname);
                my_gs.groupList.addMember(groupname, requester);
                my_gs.groupList.addOwnership(groupname, requester);
                // for userList object, it needs to add group and groupowner.
                my_gs.userList.addGroup(requester, groupname);
                my_gs.userList.addOwnership(requester, groupname);
                my_gs.groupList.addNewKey(groupname);
                
                return true;
            } else {
                return false;
            }
        } else {
            return false;
        }
    }

    //Method to create tokens
    private UserToken createToken(String username) {
        //Check that user exists
        if(my_gs.userList.checkUser(username)) {
            //Issue a new token with server's name, user's name, and user's groups
            Token yourToken = new Token(my_gs.name, username, my_gs.userList.getUserGroups(username), setTimeStamp());
            return my_gs.getSignedToken(yourToken);
        } else {
            return null;
        }
    }

    // public static void main(String args[]) {
    //     Date ts = setTimeStamp();
    //     String s1 = (String) ts.toString();
    //     System.out.println(s1);
    // }


    private Date setTimeStamp() {
        Calendar currTime=Calendar.getInstance();
        long millSecs= currTime.getTimeInMillis();
        Date timeStamp = new Date(millSecs +(45*60*1000));
        return timeStamp;
    }

    private Token createTokenWithFile(Token token, PublicKey key) {
        Token updateToken = new Token(token.getIssuer(),token.getSubject(), token.getGroups(), token.getDate(), key);
        return my_gs.getSignedToken(updateToken);
    }

    //Method to create a user
    private boolean createUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Check if requester exists
        if(my_gs.userList.checkUser(requester)) {
            //Get the user's groups
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administrator
            if(temp.contains("ADMIN")) {
                //Does user already exist?
                if(my_gs.userList.checkUser(username)) {
                    return false; //User already exists
                } else {
                    my_gs.userList.addUser(username);
                    my_gs.userList.setPassword(username, Password.getPassword());
                    return true;
                }
            } else {
                return false; //requester not an administrator
            }
        } else {
            return false; //requester does not exist
        }
    }

    //Method to delete a user
    //yourToken should be admin, username is one which is gonna be deleted.
    private boolean deleteUser(String username, UserToken yourToken) {
        String requester = yourToken.getSubject();

        //Does requester exist?
        if(my_gs.userList.checkUser(requester)) {
            ArrayList<String> temp = my_gs.userList.getUserGroups(requester);
            //requester needs to be an administer
            if(temp.contains("ADMIN")) {
                //Does user exist?
                if(my_gs.userList.checkUser(username)) {
                    //User needs deleted from the groups they belong
                    ArrayList<String> deleteFromGroups = new ArrayList<String>();

                    //This will produce a hard copy of the list of groups this user belongs
                    for(int index = 0; index < my_gs.userList.getUserGroups(username).size(); index++) {
                        deleteFromGroups.add(my_gs.userList.getUserGroups(username).get(index));
                    }

                    //Delete the user from the groups
        
                    for(int index = 0; index < deleteFromGroups.size(); index++) {
                        my_gs.groupList.removeMember(deleteFromGroups.get(index), username);
                        my_gs.groupList.addNewKey(deleteFromGroups.get(index));
                    }

                    //If groups are owned, they must be deleted
                    ArrayList<String> deleteOwnedGroup = new ArrayList<String>();

                    //Make a hard copy of the user's ownership list
                    for(int index = 0; index < my_gs.userList.getUserOwnership(username).size(); index++) {
                        deleteOwnedGroup.add(my_gs.userList.getUserOwnership(username).get(index));
                    }

                    //Delete owned groups
                    for(int index = 0; index < deleteOwnedGroup.size(); index++) {
                        //Use the delete group method. Token must be created for this action
                        deleteGroup(deleteOwnedGroup.get(index), new Token(my_gs.name, username, deleteOwnedGroup,setTimeStamp()));
                    }

                    //Delete the user from the user list
                    my_gs.userList.deleteUser(username);

                    return true;
                } else {
                    return false; //User does not exist

                }
            } else {
                return false; //requester is not an administer
            }
        } else {
            return false; //requester does not exist
        }
    }

    public boolean authToken(Token token) {
        try{
            Signature sign = Signature.getInstance("SHA256withRSA","BC");
            sign.initVerify(my_gs.getGroupServerPubKey());
            sign.update(token.convertTokentoString());

            Date timeStamp= token.getDate();
            Calendar date =Calendar.getInstance();
            long currTimeMS=date.getTimeInMillis();
            Date currTime=new Date(currTimeMS);

            boolean flag=false;
            if(currTime.compareTo(timeStamp)<0){
                flag=true;
            }
            if(sign.verify(token.getSignedT()) && flag) {
                return true;
            } else {
                return false;
            }

            // if(sign.verify(token.getSignedT())) {
            //     return true;
            // } else {
            //     return false;
            // }

        }catch (Exception e) {
			System.err.println("Error: " + e.getMessage());
			e.printStackTrace(System.err);
		}
		return false;
    }



}
