/* Group server. Server loads the users from UserList.bin.
 * If user list does not exists, it creates a new list and makes the user the server administrator.
 * On exit, the server saves the user list to file.
 */

/*
 * TODO: This file will need to be modified to save state related to
 *       groups that are created in the system
 *
 */

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupServer extends Server {

    public UserList userList;
    public GroupList groupList;
    public KeyPair keyPair;
    
    public GroupServer(int _port) {
        super(_port, "alpha");
    }

    public void start() {
        // Overwrote server.start() because if no user file exists, initial admin account needs to be created
        Security.addProvider(new BouncyCastleProvider());

        String userFile = "UserList.bin";
        String groupFile = "GroupList.bin";
        String keyFile = "GroupServerKeyList.bin";

        Scanner console = new Scanner(System.in);
        ObjectInputStream userStream;
        ObjectInputStream groupStream;
        ObjectInputStream keyStream;

        
        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        runtime.addShutdownHook(new ShutDownListener(this));

        //Open group server RSA keypair file
        try {
            FileInputStream fis = new FileInputStream(keyFile);
            keyStream = new ObjectInputStream(fis);
            keyPair = (KeyPair) keyStream.readObject();
            keyStream.close();
            fis.close();
			System.out.println("Group Server keyPair is loaded...");

        } catch(FileNotFoundException e) {
            System.out.println("Group Server keyPair file Does Not Exist. Creating Group Server keyPair List...");
            try{
                KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA", "BC");
                keyPairGen.initialize(4096);  // public key size
                keyPair = keyPairGen.generateKeyPair();
                System.out.println("Created keypair.");

            } catch(Exception ee) {
                System.out.println("Error generating RSA keypair");
                ee.printStackTrace(System.err);

            } 

            System.out.println("Saving Group Server keyPair...");
            ObjectOutputStream keyOut;

            try{
                keyOut = new ObjectOutputStream(new FileOutputStream(keyFile));
                keyOut.writeObject(keyPair);
                keyOut.close();

            } catch(Exception ee) {
                System.out.println("Error writing to kaypair list");
                ee.printStackTrace(System.err);

            }

        } catch(Exception e) {
            System.out.println("Error reading from Group Server keyPair list");
            e.printStackTrace(System.err);
            System.exit(-1);
        } 

        //Open user list and group list, otherwise create admin.
        try {
            FileInputStream fis = new FileInputStream(userFile);
            userStream = new ObjectInputStream(fis);
            userList = (UserList) userStream.readObject();

            fis = new FileInputStream(groupFile);
            groupStream= new ObjectInputStream(fis);
            groupList = (GroupList) groupStream.readObject();

        } catch(FileNotFoundException e) {
            groupList = new GroupList();
            groupList.addGroup("ADMIN");
            System.out.println("Grouplist File Does Not Exist. Creating GroupList...");
            System.out.println("No groups currently exist. ADMIN group being created, you will be added to ADMIN group");

            System.out.println("UserList File Does Not Exist. Creating UserList...");
            System.out.println("No users currently exist. Your account will be the administrator.");
            System.out.print("Enter your username: ");
            String username = console.next();

            userList = new UserList();
            userList.addUser(username);

            //Create a new list, add current user to the ADMIN group. They now own the ADMIN group.
            userList.addGroup(username, "ADMIN");
            userList.addOwnership(username, "ADMIN");
            groupList.addMember("ADMIN",username);
            groupList.addOwnership("ADMIN",username);
            String pass= Password.getPassword();
            userList.setPassword(username, pass); //Sets Admins new password
            System.out.println("Your password is: "+ pass );
            groupList.addNewKey("ADMIN");
            ArrayList<SecretKey> list=new ArrayList<SecretKey>();
            list=groupList.getGKeys("ADMIN");
            System.out.println(list.get(0));    

        } catch(IOException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from UserList file");
            System.exit(-1);
        }


        //Autosave Daemon. Saves lists every 5 minutes
        AutoSave aSave = new AutoSave(this);
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            GroupThread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new GroupThread(sock, this, keyPair.getPrivate());
                thread.start();
            }
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }

    }

    public PublicKey getGroupServerPubKey() {
        return keyPair.getPublic();
    }

    public Token getSignedToken(Token token) {
        try{
            Signature signature = Signature.getInstance("SHA256withRSA","BC");
            signature.initSign(keyPair.getPrivate());
            signature.update(token.convertTokentoString());
            token.setSignature(signature.sign());
            return token;
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
        return null;
    }
    public Integer getNonce(){
        SecureRandom random = new SecureRandom();
        int num = random.nextInt(200000000); //  range ?
        return num;
    }

}

//This thread saves the user list
class ShutDownListener extends Thread {
    public GroupServer my_gs;

    public ShutDownListener (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;
        try {
            outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
            outStream.writeObject(my_gs.userList);
            outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
            outStream.writeObject(my_gs.groupList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSave extends Thread {
    public GroupServer my_gs;

    public AutoSave (GroupServer _gs) {
        my_gs = _gs;
    }

    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave group and user lists...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("UserList.bin"));
                    outStream.writeObject(my_gs.userList);
                    outStream = new ObjectOutputStream(new FileOutputStream("GroupList.bin"));
                    outStream.writeObject(my_gs.groupList);
                } catch(Exception e) {
                    System.err.println("Error: " + e.getMessage());
                    e.printStackTrace(System.err);
                }

            } catch(Exception e) {
                System.out.println("Autosave Interrupted");
            }
        } while(true);
    }
}
