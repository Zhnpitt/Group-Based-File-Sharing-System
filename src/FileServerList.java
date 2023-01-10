import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Arrays;

public class FileServerList implements java.io.Serializable {
    private static final long serialVersionUID = 5634179927600343803L;
    public ArrayList<FileServerID> fileServerList;

    public FileServerList() {
        fileServerList = new ArrayList<FileServerID>();
    }

    public synchronized void addServer(FileServerID fsid) {
        fileServerList.add(fsid);
    }

    public synchronized boolean hasServer(FileServerID fsid) {
        for (int i = 0; i < fileServerList.size(); i++) {
            if (fileServerList.get(i).getPort() == fsid.getPort() &&
                fileServerList.get(i).getAddr().equals(fsid.getAddr())) {
                // Compare byte arrays from keys
                if (Arrays.equals(fileServerList.get(i).getKey().getEncoded(),
                                  fsid.getKey().getEncoded())) {
                    return true;
                }
            }
        }
        return false;
    }
}

class FileServerID implements java.io.Serializable {
    private static final long serialVersionUID = -3998215986699986336L;
    public String address;
    public int port;
    public PublicKey key;
    
    public FileServerID(String _address, int _port, PublicKey _key) {
        address = _address;
        port = _port;
        key = _key;
    }
    
    public String getAddr() {
        return address;
    }
    
    public int getPort() {
        return port;
    }
    
    public PublicKey getKey() {
        return key;
    }
}