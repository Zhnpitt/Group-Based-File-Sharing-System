/* FileServer loads files from FileList.bin.  Stores files in shared_files directory. */

import java.io.File;
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
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.util.Scanner;

import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class FileServer extends Server {

    public static FileList fileList;
    private KeyPair keys = null;
    public static String groupServerAdd;
    public static int groupServerPort;
    public static PublicKey gspPublicKey;

    public FileServer(int _port) {
        super(_port, "omega");
    }

    public FileServer(int _port, String groupServerAdd, int groupServerPort) { // pass gsAdd and gsPort to FS
        super(_port, "omega");
        this.groupServerAdd = groupServerAdd;
        this.groupServerPort = groupServerPort;
    }

    public void showPubFS() {
        System.out.println(getFileServerPubKey());
    }

    public void start() {

        String fileFile = "FileList.bin";
        String keyFile = "FileServer"+ port + "KeyList.bin"; // server port
        ObjectInputStream fileStream;
        Security.addProvider(new BouncyCastleProvider());

        //This runs a thread that saves the lists on program exit
        Runtime runtime = Runtime.getRuntime();
        Thread catchExit = new Thread(new ShutDownListenerFS());
        runtime.addShutdownHook(catchExit);

        //Open user file to get user list
        try {
            FileInputStream fis = new FileInputStream(fileFile);
            fileStream = new ObjectInputStream(fis);
            fileList = (FileList)fileStream.readObject();
        } catch(FileNotFoundException e) {
            System.out.println("FileList Does Not Exist. Creating FileList...");

            fileList = new FileList();

        } catch(IOException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        } catch(ClassNotFoundException e) {
            System.out.println("Error reading from FileList file");
            System.exit(-1);
        }

        File file = new File("shared_files");
        if (file.mkdir()) {
            System.out.println("Created new shared_files directory");
        } else if (file.exists()) {
            System.out.println("Found shared_files directory");
        } else {
            System.out.println("Error creating shared_files directory");
        }

        // open RSA key file
        try {
            FileInputStream fis = new FileInputStream(keyFile);
            fileStream = new ObjectInputStream(fis);
            keys = (KeyPair) fileStream.readObject();
            fileStream.close();
            fis.close();
            System.out.println("File Server keyPair is loaded...");
        } catch (FileNotFoundException e) {
            System.out.println(keyFile+ " File Does Not Exist. Creating" + keyFile+ " List...");

            try{
                KeyPairGenerator keyGenRSA = KeyPairGenerator.getInstance("RSA","BC");
                keyGenRSA.initialize(4096); // key size
                keys = keyGenRSA.generateKeyPair();
                System.out.println("Created keyPair.");

            } catch (Exception ee) {
                System.out.println("Error generating RSA keypair.");
                ee.printStackTrace(System.err);
                System.exit(-1);
            }

            System.out.println("Saving "+ keyFile + " ...");
            ObjectOutputStream keyOut;

            try{
                keyOut =  new ObjectOutputStream(new FileOutputStream(keyFile));
                keyOut.writeObject(keys);
                keyOut.close();
            } catch (Exception ee) {
                System.out.println("Error writing to kaypair list");
                ee.printStackTrace(System.err);
                System.exit(-1);
            }
        }  catch(Exception e) {
            System.out.println("Error reading from "+ keyFile + " file");
            e.printStackTrace(System.err);
            System.exit(-1);
        }

        // get Group server public key.
        GroupClient groupClient = new GroupClient();
        Scanner input = new Scanner(System.in);
        System.out.println( "please input group server name:");
        groupServerAdd = input.nextLine();
        System.out.println("group server port:");
        groupServerPort = input.nextInt();
        groupClient.connect(groupServerAdd, groupServerPort); // 
        if (groupClient.isConnected()) {
            gspPublicKey = groupClient.getPubKey();
            if (gspPublicKey == null) {
                System.out.println("Error: Group Server public key not retrieved.");
                groupClient.disconnect();
                System.exit(-1);
            }
            System.out.println("Group Server key retrieved.");
			groupClient.disconnect();
        } else {
            System.out.println("Error: Group server not reached at the given address.");
        }

        System.out.println( "File Server public Key: ");
        // showPubFS();

        //Autosave Daemon. Saves lists every 5 minutes
        AutoSaveFS aSave = new AutoSaveFS();
        aSave.setDaemon(true);
        aSave.start();

        //This block listens for connections and creates threads on new connections
        try {
            final ServerSocket serverSock = new ServerSocket(port);
            System.out.printf("%s up and running\n", this.getClass().getName());

            Socket sock = null;
            Thread thread = null;

            while(true) {
                sock = serverSock.accept();
                thread = new FileThread(sock, this, keys.getPrivate(), gspPublicKey);
                thread.start();
            }

        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }

    public PublicKey getFileServerPubKey() {
        return keys.getPublic();
    }


}

//This thread saves user and group lists
class ShutDownListenerFS implements Runnable {
    public void run() {
        System.out.println("Shutting down server");
        ObjectOutputStream outStream;

        try {
            outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
            outStream.writeObject(FileServer.fileList);
        } catch(Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace(System.err);
        }
    }
}

class AutoSaveFS extends Thread {
    public void run() {
        do {
            try {
                Thread.sleep(300000); //Save group and user lists every 5 minutes
                System.out.println("Autosave file list...");
                ObjectOutputStream outStream;
                try {
                    outStream = new ObjectOutputStream(new FileOutputStream("FileList.bin"));
                    outStream.writeObject(FileServer.fileList);
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
