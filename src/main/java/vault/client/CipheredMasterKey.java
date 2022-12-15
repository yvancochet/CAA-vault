package vault.client;

public class CipheredMasterKey {
    public String ciphered_key;
    public String iv;

    public CipheredMasterKey(String ciphered_key, String iv){
        this.ciphered_key = ciphered_key;
        this.iv = iv;
    }
}
