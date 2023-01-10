import java.io.Serializable;
import java.util.ArrayList;
import java.util.Scanner;

public class Tester implements Serializable{
static Scanner input= new Scanner(System.in);
static String user;

public static void main(String[] arg) {

   
    
    GroupClient gc = new GroupClient();
    String b = "localhost";
    System.out.println("Group Server is connected" + " " + gc.connect(b,11722));

    FileClient sc = new FileClient();
    String a = "localhost";
    System.out.println(" File Sever is connected" + " "+sc.connect(a,14506));

    System.out.println("username");
    user=input.nextLine();
    // UserToken token= gc.getToken(user);
    //sc.delete("Hello",token);
    //System.out.println(gc.createUser("Thor", token));
    //sc.download("Steelers","Hello.txt" ,token);
//    ArrayList<ShareFile> l=new ArrayList<ShareFile>();
//     ArrayList<String> k=new ArrayList<String>();
//     l=FileServer.fileList.getFiles();
//     for(ShareFile file:l){
//        k.add(file.getPath());
//    }

    

//     System.out.print(k);
    
    
    //sc.upload("/Users/tylercourtney/Documents/testFile.txt", "Testfile", "Cats", token);
    //System.out.println(sc.listFiles(token));
    //System.out.println(gc.deleteUserFromGroup("Abby", "GroupB", token));
    //System.out.println(gc.createGroup("GroupB", token));
    //System.out.println(gc.deleteGroup("GroupA", token));
    // System.out.println(gc.listMembers("GroupA", token));
    //System.out.println(gc.addUserToGroup("Abby","GroupB", token));
    //System.out.println(token.getGroups());
    // if (token != null){
    // System.out.println("Yes");
    // } else{
    // System.out.println("no");

    } 




    //String first = "admin";
    //UserToken admin = gc.getToken(first);
    

    //gc.createUser("test1", admin);
    //gc.createUser("test2", admin);

    //UserToken test1= gc.getToken("test1");
    //UserToken test2= gc.getToken("test2");
    //System.out.println(test2);
    // System.out.println("username:");
    // user=input.nextLine();
    // UserToken tok= gc.getToken(user);

   //gc.createGroup("group1", test1);
    //gc.addUserToGroup("test2", "group1", tok);

    //System.out.println(test1.getIssuer());
    // System.out.println(admin.getGroups());
    // System.out.println(tok.getGroups());
    
    //sc.upload("/Users/tylercourtney/Documents/testFile.txt", "testFile2", "group1", tok);
    //System.out.println(sc.listFiles(test1));
    //sc.delete("testFile2", tok);
    // System.out.println(sc.listFiles(tok));







   
   
   
   
   
   
   
    // UserToken admin = gc.getToken(first);
    //  System.out.println(gc.createUser("test1", admin));
    //  System.out.println(gc.createUser("test2", admin));
    //  System.out.println(gc.createUser("test3", admin));
    //  UserToken test1 =gc.getToken("test1");
    //  UserToken test2=gc.getToken("test2");

    //  System.out.println(gc.createGroup("group3", admin));


  
    //System.out.println(gc.addUserToGroup("test1", "group3", admin));
    // gc.addUserToGroup("third", "group3", admin);
    // gc.addUserToGroup("four", "group3", admin);
    // System.out.println(gc.listMembers("ADMIN", admin));
    
    //System.out.println(gc.deleteUserFromGroup("second", "ADMIN", admin));
    //System.out.println(gc.deleteUserFromGroup("third", "ADMIN", admin));
    // System.out.println(gc.listMembers("ADMIN", admin));
    // System.out.println(gc.listMembers("group3", admin));
    //System.out.println(gc.deleteGroup("ADMIN", admin));
    //System.out.println(gc.listMembers("ADMIN", admin));
    // first disconnect, then re-connect

}
