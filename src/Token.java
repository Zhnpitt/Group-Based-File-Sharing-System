import java.io.Serializable;
import java.security.PublicKey;
import java.util.Date;
import java.util.Calendar;
import java.util.List;

public class Token implements UserToken, Serializable{
    String issuerToken;
    String subjectToken;
    List<String> groupList;
    byte[] signedToken;
    Date date;
    PublicKey serverKey;
    private String FSName;
    private int FSport;

    public Token(String issuerToken, String subjectToken, List<String> groupList, Date date){
        this.issuerToken = issuerToken;
        this.subjectToken = subjectToken;
        this.groupList= groupList;
        this.date=date;
    }

    public Token(String issuerToken, String subjectToken, List<String> groupList, Date date, byte[] signedToken) {
        this.issuerToken = issuerToken;
        this.subjectToken = subjectToken;
        this.groupList= groupList;
        this.date=date;
        this.signedToken = signedToken;
    }

    public Token(String issuerToken, String subjectToken, List<String> groupList, Date date, PublicKey key) {
        this.issuerToken = issuerToken;
        this.subjectToken = subjectToken;
        this.groupList= groupList;
        this.date=date;
        this.serverKey=key;
    }

    public void setKey(PublicKey key){
        serverKey=key;
    }


    public byte[] getSignedT() {
        return signedToken;
    }

    public void setSignature(byte[] SToken){
        signedToken = SToken;
    }

    public String getIssuer() {
        return issuerToken;
    }

    public String getSubject(){
        return subjectToken;
    }

    public List<String> getGroups(){
        return groupList;
    }

    public String getFSName(){
        return FSName;
    }
    public int getFSPort(){
        return FSport;
    }

    public String getServerKey(){
        return serverKey.toString();
    }

    public Date getDate(){
        return date;
    }

    public byte[] convertTokentoString (){
        StringBuilder sb = new StringBuilder();
        sb.append(issuerToken);
        sb.append(subjectToken);
        for (int i =0; i< groupList.size();i++) {
            sb.append(groupList.get(i));
        }
        sb.append(date.toString());
        sb.append(serverKey);

        // sb.append(FSName);
        // sb.append(FSport);
        // sb.append(serverKey);
        // sb.append(date.toString());

        return sb.toString().getBytes();
    }
}