import javax.crypto.SecretKey;

public class KeyChallengePack implements java.io.Serializable {
    private static final long serialVersionUID = -1931037726335089122L;
    private int challenge;
    private SecretKey sessionKey;
    private SecretKey integrityKey;

    public KeyChallengePack(int challenge, SecretKey sessionKey, SecretKey integrityKey){
        this.challenge = challenge;
        this.sessionKey = sessionKey;
        this.integrityKey = integrityKey;
    }

    public KeyChallengePack(int challenge, SecretKey sessionKey){
        this.challenge = challenge;
        this.sessionKey = sessionKey;
    }

    public Integer getChallenge(){
        return challenge;
    }

    public SecretKey getSecretKey(){
        return sessionKey;
    }

    public SecretKey getIntegrityKey() {
        return integrityKey;
    }

}
