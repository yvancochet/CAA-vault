/**
 * Author : Yvan Cochet
 * Project : HEIG-VD - CAA - mini project- vault
 * Date : 17.12.2022
 */

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