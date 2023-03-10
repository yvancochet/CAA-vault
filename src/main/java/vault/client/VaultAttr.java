/**
 * Author : Yvan Cochet
 * Project : HEIG-VD - CAA - mini project- vault
 * Date : 17.12.2022
 */

package vault.client;

/**
 * Class to store sensitive vault data
 * The goal of using such a class is to dump the object when exiting a company's vault
 */
class VaultAttr {
    byte[] masterKey = null;
    byte[] unlockKey = null;
    int nUsers = 0;
}
