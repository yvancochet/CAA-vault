/**
 * Author : Yvan Cochet
 * Project : HEIG-VD - CAA - mini project- vault
 * Date : 17.12.2022
 */

package vault.client;

public class CipheredUserPointList {
    public CipheredUserPoint[] userPoints;
    public CipheredUserPointList(int size) {
        userPoints = new CipheredUserPoint[size];
    }
}
