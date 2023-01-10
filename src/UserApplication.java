import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

import javax.crypto.SecretKey;

public class UserApplication {
    static GroupClient gc;
    static FileClient fc;
    private static Scanner input = new Scanner(System.in);
    static String user;
    static UserToken token;
    static String serverName;
    static int portNum;
    static PublicKey pubKey;
    static int nonce;
    static SecretKey groupSK;
    static SecretKey fileSK;
    static String password;

    static ArrayList<SecretKey> groupKeys = new ArrayList<SecretKey>();

    

    public static void main(String[] arg){
        fc = new FileClient();
        gc = new GroupClient();

        while(true){
            System.out.println("\nPlease select a function (Case Sensitive)");
            System.out.println("G - Connect to group server for group and user maintenance\nYou may connect to file server After connecting to group server");
            System.out.println("X - Exit");
            String x = input.nextLine();
            String p = input.nextLine();

            if (p.equals("G")){
                groupServCon();
            } else if (p.equals("X")){
                return;
            } else {
                System.out.println("Please select a function from above");
                
            }
        }
    }
    private static void groupServCon(){
        System.out.println("Please input username");
        user = input.nextLine();
        System.out.println("Password:");
        password = input.nextLine();
        System.out.println( "server name:");
        serverName = input.nextLine();
        System.out.println("port:");
        portNum = input.nextInt();
        
        try{
            gc.connect(serverName, portNum);
        }catch (Exception e){
           // System.out.println("Cannot Connect, ensure server name and port number are correct");
        }
        
        if(!gc.sendSessionKeyToGroup()){
            gc.disconnect();
        }
        //System.out.println("Session key successfully transferred. Retriving token");
        
        token = gc.getToken(user, password); //Get token for user

        if (token == null) {
            System.out.println("Username not recognized or password is incorrect.");
            gc.disconnect();
        } 
        else if(token!= null){ //If user exists they can get token and continue
            while(true){
                System.out.println("X - Exit\n~~ADMIN ONLY PRIVELEGES~~\nC - Create a new user\nD - Delete a user\n~~NORMAL OPERATIONS~~\nG - Create a new Group\n F - Delete a group\n A - Add a user to group\n R - Delete user from group\n L - List members of group\n Y - Manage files (Connect to file server)\n P- Change Password");
                System.out.println("Please select a function you want to use");
                String a = input.nextLine(); 
                String func = input.nextLine();
            
                if (func.equals("X")){
                    gc.disconnect(); 
                    System.out.println("Disconnected from group server"); 
                    break;
                }else if(func.equals("C")){
                    if(checkAdmin(token)){
                        createU(token);
                    }else {
                        System.out.println("You are not an Admin");} //gc.connect(user, portNum);}
           
                    } else if(func.equals("D")){
                        if(checkAdmin(token)){
                            deleteU(token);
                        }else {
                            System.out.println("You are not an Admin");
                        } //gc.connect(user, portNum);}
                    }else if(func.equals("G")){
                        createG(token); 
                        
                    }else if(func.equals("F")){
                        deleteG(token);
                    }else if(func.equals("A")){
                        addUserG(token);
                    }else if(func.equals("R")){
                        deleteUserG(token);
                    }else if(func.equals("L")){
                        listU(token); 
                        
                    }else if(func.equals("P")){
                        System.out.println("please enter a new 12 digit password");
                        String newPass=input.nextLine();
                        gc.changePassword(newPass, token);
                        
                    }else if(func.equals("Y")){
                        System.out.println("Enter File server name");
                        String fServName = input.nextLine();
                        System.out.print("Please enter port number");
                        int fportNum = input.nextInt();
                        System.out.print("Enter Name of Group you want to upload/download for");
                        String x=input.nextLine();
                        String gName=input.nextLine();
                        System.out.println(gName);

                        groupKeys = gc.sendKeyArray(gName, token); // group server create key for encrypting file stored in file server.

                        PublicKey FSKEY = getFSKeyOOB(fServName,fportNum); // kind of out of band wway to get FS pubKey
                        token = gc.getTokenWithFile(token, FSKEY);
                        // System.out.println(groupKeys.get(0));

                        gc.disconnect();

                
                        if (fc.connect(fServName, fportNum)) {
                            String fs = "FileServerList.bin";
                            ObjectInputStream ois;
                            PublicKey FSKey = fc.getPubKey();
                            FileServerID fileServ = new FileServerID(fServName, fportNum, FSKey);

                            try {
                                FileInputStream fis = new FileInputStream(fs);
                                ois = new ObjectInputStream(fis);
                                FileServerList fsList = (FileServerList)ois.readObject();
                                ois.close();
                                fis.close();
                                
                                if (fsList.hasServer(fileServ)) {
                                    
                                    System.out.println("File Server is known. Connecting");
                                }
                                else {
                                    
                                    System.out.println("File Server Unknown");
                                    System.out.println("Add server to list? y/n");
                                    String answer = input.nextLine();
                                    if (answer.charAt(0) == 'y' || answer.charAt(0) == 'Y') {
                                        FileOutputStream fileOS;
                                        ObjectOutputStream objOs;
                                        try {
                                            FileServerList fslist = new FileServerList();
                                            fslist.addServer(fileServ);
                                            fileOS = new FileOutputStream(fs);
                                            objOs = new ObjectOutputStream(fileOS);
                                            objOs.writeObject(fslist);
                                            objOs.close();
                                            fileOS.close();
                                            System.out.println("File Server added to FileServerList");
                                        }
                                        catch(Exception e) { 
                                            e.printStackTrace();
                                        }
                                    }
                                    else {
                                        fc.disconnect();
                                    }
                                }
                            }
                            catch(FileNotFoundException e) {
                                System.out.println("Creating file server list");
                                FileOutputStream fos;
                                ObjectOutputStream oos;
                                try {
                                    FileServerList fsl = new FileServerList();
                                    fsl.addServer(fileServ);
                                    fos = new FileOutputStream(fs);
                                    oos = new ObjectOutputStream(fos);
                                    oos.writeObject(fsl);
                                    oos.close();
                                    fos.close();
                                }catch(Exception er) {
                        
                                    er.printStackTrace();
                                   fc.disconnect();
                                }
                            }catch(Exception err) {
                              fc.disconnect();
                            }
                            
                            // get session key
                            if (!fc.sendSessionkeyToFS()) {
                                fc.disconnect();
                            }
                            
                                System.out.println("Session done");
                             while (true) {
                                
                                System.out.println("X - Exit\nU - Upload File\nD - Download File\nR - Delete File\nL - List Files");
                                System.out.println("Please select a function you want to use");
                                String l = input.nextLine(); 
                                String funct = input.nextLine();
                                
                                
                                if(funct.equals("X")){
                                    fc.disconnect(); 
                                    System.out.println("Disconnectng from file server");
                                    break;
                                }else if(funct.equals("U")){
                                    upFile(token); 
                                }else if(funct.equals("R")){
                                    delFile(token);
                                }else if(funct.equals("L")){
                                    System.out.println(fc.listFiles(token));
                                }else if(funct.equals("D")){
                                    downFile(token);
                                }
                                System.out.println("please enter a correct command");
                            }
                        }else { // error connecting
                            System.out.println("Cannot Connect");
                            
                           
                        }


                   
            }    }
        }else {
            System.out.println("Invalid token, assure user has been created by admin");
        }
    }    

    private static boolean checkAdmin (UserToken token) { //Check admin priveleges
        List<String> list = new ArrayList<>();
        list = token.getGroups();
        for(String g:list){
            if(g.equals("ADMIN")){
                return true;
            } 
        }
        return false;
    }

    private static void createU(UserToken token){ //Helper for creating user
        System.out.println("Please enter name of new user");
        String username= input.nextLine();
        if (gc.createUser(username, token)){
            System.out.println("User successfuly created");
        }else{
            System.out.println("User creation unsuccessful");
        }
    }
        
    private static void deleteU(UserToken token){
        System.out.println("Please enter the name of the user you want to delete");
        String username= input.nextLine();
        if(username!=token.getSubject() &&  gc.deleteUser(username, token)){
                System.out.println("User successfuly deleted");
            }else{
                System.out.println("Deletion unsuccessful");
            }
        } 

    private static void createG(UserToken token){
        System.out.println("Please enter the name of your new group");
        String group=input.nextLine();
        if (gc.createGroup(group,token)){
            System.out.println("Group successfuly created");
        }else{
            System.out.println("Group creation unsuccessful");
        }
    }

    private static void deleteG(UserToken token){
        System.out.println("Please enter the name of the group you want to delete");
        String group= input.nextLine();
        if (gc.deleteGroup(group,token)){
            System.out.println("Group successfuly deleted"); 
        }else{
            System.out.println("Deletion unsuccessful");
        }
    }

    private static void addUserG(UserToken token){
        System.out.println("Please enter the name of the group you want to add the user to");
        String group=input.nextLine();
        System.out.println("Please enter the name of the user you want to add to "+ group);
        String user=input.nextLine();
        if(gc.addUserToGroup(user, group, token)){
            System.out.println(user + " successfully added to "+ group);

        }else{
            System.out.println("User could not be added");
        }
    }

    private static void deleteUserG(UserToken token){
        System.out.println("Please enter the name of the group you want to delete the user from");
        String group=input.nextLine();
        System.out.println("Please enter the name of the user you want to delete from "+ group);
        String user=input.nextLine();
            if(!user.equals(token.getSubject())){
                if(gc.deleteUserFromGroup(user, group, token)){
                System.out.println(user + " deleted from "+ group); 
                } else{
                    System.out.println("User could not be deleted");
                }
            }else{
                System.out.println("Cannot delete yourself");
            }       
    }
        
    private static void listU(UserToken token){
        List<String> list=new ArrayList<>();
        System.out.println("Please enter the name of the group you want to list users from");
        String group=input.nextLine();
        list=gc.listMembers(group, token);
        if(!list.isEmpty()){
            System.out.println(gc.listMembers(group, token));
        } else{
            System.out.println("cannot list members of "+group);
        }                  
    }

    private static void upFile(UserToken token){

        System.out.println("Please provide pathname to file you want to upload");
        String p=input.nextLine();
        String path=input.nextLine();
        System.out.println("Please enter the name you would like to save the file to the server");
        String dest=input.nextLine();
        System.out.println("Please enter the name of the group you want to share this file with");
        String group=input.nextLine();
        if(fc.upload(path, dest, group, token, groupKeys)){
            System.out.println("Successfully Uploaded"); System.out.println(dest); 
        }else{
            System.out.println("File Failed to upload");
        }
    }

    private static void delFile(UserToken token){
        
        System.out.println("Please provide name of the file you want to delete");
        String name=input.nextLine();
        if(fc.delete(name,token)){
            System.out.println("Successfully Deleted");
        }else{
            System.out.println("File Failed to be deleted");
        }
    }

    private static void downFile(UserToken token){
        System.out.println("Please provide name of the file you want to download");
        String name=input.nextLine();
        System.out.println("Please enter name you want to save file as");
        String dest = input.nextLine();
        if(fc.download(name,dest,token,groupKeys)){
            System.out.println("Successfully downloaded");
        }else{
            System.out.println("File Failed to be downloaded");
        }
    }

    private static PublicKey getFSKeyOOB(String name, int port){
        fc.connect(name, port);
        PublicKey key = fc.getPubKey();
        fc.disconnect();
        return key;
    }   
}
