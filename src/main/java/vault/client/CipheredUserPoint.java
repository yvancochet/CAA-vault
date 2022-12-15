package vault.client;

public class CipheredUserPoint {
    public String username;
    public String cipher_point;
    public String iv;

    public CipheredUserPoint(String username, String cipher_point, String iv/*, String tag*/) {
        this.username = username;
        this.cipher_point = cipher_point;
        this.iv = iv;
    }
}