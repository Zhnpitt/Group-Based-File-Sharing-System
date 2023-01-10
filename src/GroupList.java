import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.ArrayList;
import java.util.Hashtable;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GroupList implements java.io.Serializable {
	private static final long serialVersionUID = -2536806905954268497L;
	private Hashtable<String, Group> list = new Hashtable<String, Group>();

	public synchronized void addGroup(String groupname) {
		Group newGroup = new Group();
		list.put(groupname, newGroup);
	}

	public synchronized void deleteGroup(String groupname) {
		list.remove(groupname);
	}

	public synchronized boolean checkGroup(String groupname) {
		if (list.containsKey(groupname)) {
			return true;
		} else {
			return false;
		}
	}

	public synchronized ArrayList<String> getGroupUsers(String groupname) {
		return list.get(groupname).getUsers();
	}

	public synchronized ArrayList<String> getGroupOwnership(String groupname) {
		return list.get(groupname).getOwnership();
	}

	public synchronized void addMember(String group, String username) {
		list.get(group).addMember(username);
	}

	public synchronized void removeMember(String group, String username) {
		list.get(group).removeMember(username);
	}

	public synchronized void addOwnership(String group, String username) {
		list.get(group).addOwnership(username);
	}

	public synchronized void removeOwnership(String group, String username) {
		list.get(group).removeOwnership(username);
	}

	public synchronized ArrayList<SecretKey> getGKeys(String group){
		return list.get(group).getKeys();
	}
	public synchronized void addNewKey(String group){
		list.get(group).addKey();
	}

	class Group implements java.io.Serializable {
		private static final long serialVersionUID = -6699986336399821598L;
		private ArrayList<String> users;
		private ArrayList<String> ownership;
		private ArrayList<SecretKey> keys;

		public Group() {
			users = new ArrayList<String>();
			ownership = new ArrayList<String>();
			keys=new ArrayList<SecretKey>();
		}

		public ArrayList<SecretKey>getKeys(){
			return keys;
		}

		public void addKey(){
			keys.add(getGroupKey());
		}

		public ArrayList<String> getUsers() {
			return users;
		}

		public ArrayList<String> getOwnership() {
			return ownership;
		}

		public void addMember(String user) {
			users.add(user);
		}

		public void removeMember(String user) {
			if (!users.isEmpty()) {
				if (users.contains(user)) {
					users.remove(users.indexOf(user));
				}
			}
		}

		public void addOwnership(String user) {
			ownership.add(user);
		}

		public void removeOwnership(String user) {
			if (!ownership.isEmpty()) {
				if (ownership.contains(user)) {
					ownership.remove(ownership.indexOf(user));
				}
			}
		}

	}

	public SecretKey getGroupKey(){
        Security.addProvider(new BouncyCastleProvider());
        KeyGenerator keyGen;
        try {
            keyGen = KeyGenerator.getInstance("AES","BC");
            keyGen.init(128);
            return keyGen.generateKey();
           
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException ee){
            ee.printStackTrace();
        }
        return null;
    }

}