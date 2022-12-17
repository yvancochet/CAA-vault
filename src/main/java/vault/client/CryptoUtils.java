/**
 * Author : Yvan Cochet
 * Project : HEIG-VD - CAA - mini project- vault
 * Date : 17.12.2022
 */

package vault.client;

import at.favre.lib.crypto.HKDF;
import com.codahale.shamir.Scheme;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;


class CryptoUtils {
    private static final int KEYBITSIZE = 256;
    private static final int IVBITSIZE = 128;
    private static final int TAGSIZE = 128;

    private static boolean assertKeySize(byte[] key){
        if(key.length != KEYBITSIZE/8){
            System.out.println("Error : key size doesn't match requirement [256 bit]");
            return true;
        }
        return false;
    }

    /**
     * Generate AES key
     * @param keyBitSize size of the key to generate
     * @return AES key as byte[]
     */
    private byte[] AESKeyGenerator(int keyBitSize){
        KeyGenerator keyGenerator;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        }
        catch(Exception e){
            System.out.println("Error aes_key_generator : " + e);
            return null;
        }
        keyGenerator.init(keyBitSize);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
    }

    /**
     * Simplified AES key generator size for this project [256 bit keys]
     * @return AES key as byte[]
     */
    byte[] generateAESKey(){
        return AESKeyGenerator(KEYBITSIZE);
    }

    /**
     * Recover unlock_key with Shamir Secret sharing shares
     * @param nbPoints Total number of point generated initially
     * @param nbPointsToRecover Number of point to recover unlock_key
     * @param parts HashMap containing the points + id
     * @return unlock_key as byte[]
     */
    byte[] recoverUnlockKey(int nbPoints, int nbPointsToRecover, Map<Integer, byte[]> parts){
        if(parts.size() < nbPointsToRecover){
            System.out.println("Error : not enough points to recover unlock_key");
            return null;
        }

        Scheme scheme = new Scheme(new SecureRandom(), nbPoints, nbPointsToRecover);
        return scheme.join(parts);
    }

    /**
     * Generate a specific file key using HKDF derivation function
     * @param mk Vault's master key
     * @param filename Filename to cipher
     * @return Generated key as byte[]
     */
    byte[] generateFileKey(byte[] mk, String filename){
        HKDF hkdf = HKDF.fromHmacSha256();
        byte[] pseudoRandomKey = hkdf.extract(mk, filename.getBytes(StandardCharsets.UTF_8));
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
        return new SecretKeySpec(expandedAesKey, "AES").getEncoded(); //AES-256 key
    }

    /**
     * Generate Shamir shares (points)
     * @param nbPoints Number of points (users(
     * @param nbPointsToRecover Number of points needed to recover secret (users)
     * @param secret Secret to part into shares
     * @return HashMap containing the points + id
     */
    Map<Integer, byte[]> generateShamirPoints(int nbPoints, int nbPointsToRecover, byte[] secret){
        Scheme scheme = new Scheme(new SecureRandom(), nbPoints, nbPointsToRecover);
        return scheme.split(secret);
    }

    /**
     * Hash input using sha256
     * @param str string to hash
     * @return hash as byte[]
     */
    byte[] sha256(String str){
        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        }
        catch(Exception e){
            System.out.println("Error sha256 : " + e);
            return null;
        }
        sha.update(str.getBytes(StandardCharsets.UTF_8));
        return sha.digest();
    }

    /**
     * Generate IVBITSIZE/8 IV [128 bit]
     * @return IV as IvParameterSpec
     */
    IvParameterSpec generateIV() {
        byte[] iv = new byte[IVBITSIZE/8];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    /**
     * Cipher file to file using AES-256-GCM
     * @param key Key used to cipher data
     * @param inputPath Clear file path
     * @param outputPath Ciphered file output path
     */
    void AES256GCMEncrypt(byte[] key, String inputPath, String outputPath){
        if(assertKeySize(key))
            return;

        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        IvParameterSpec iv = generateIV();
        Cipher cipher;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secKey, parameterSpec);
        }
        catch(Exception e){
            System.out.println("AES256GCM_File_Encrypt encryption error : " + e);
            return;
        }
        FileInputStream inputStream = null;
        FileOutputStream outputStream = null;
        try {
            inputStream = new FileInputStream(inputFile);
            outputStream = new FileOutputStream(outputFile);
            byte[] buffer = new byte[64];
            int bytesRead;
            outputStream.write(iv.getIV());
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] cipherText = cipher.doFinal();

            if (cipherText != null){
                outputStream.write(cipherText);
            }
        }catch(Exception e) {
            System.out.println("Error AES256GCM_File_Encrypt: " + e);
        }finally {
            try {
                if (inputStream != null){ inputStream.close(); inputFile.delete();}
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Encrypt: " + e);
            }
            try {
                if (outputStream != null) outputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Encrypt: " + e);
            }
        }
    }

    /**
     * Decipher file to file using AES-256-GCM
     * @param key Key used to decipher data
     * @param inputPath Ciphered file path
     * @param outputPath Clear file output path
     */
    void AES256GCMDecrypt(byte[] key, String inputPath, String outputPath){
        if(assertKeySize(key))
            return;

        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        Cipher cipher;

        FileInputStream inputStream = null;
        FileOutputStream outputStream = null;
        try {
            inputStream = new FileInputStream(inputFile);
            outputStream = new FileOutputStream(outputFile);

            //Read first 16 byte to get iv
            byte[] ivBuffer = new byte[IVBITSIZE/8];
            int bytesRead;
            bytesRead = inputStream.read(ivBuffer);
            if(bytesRead < IVBITSIZE/8){
                System.out.println("Error : missing IV");
                return;
            }
            IvParameterSpec iv = new IvParameterSpec(ivBuffer);

            try {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
                cipher.init(Cipher.DECRYPT_MODE, secKey, parameterSpec);
            }
            catch(Exception e){
                System.out.println("AES256GCM_File_Decrypt decryption error : " + e);
                return;
            }
            byte[] buffer = new byte[64];
            while ((bytesRead = inputStream.read(buffer)) != -1) {
                byte[] output = cipher.update(buffer, 0, bytesRead);
                if (output != null) {
                    outputStream.write(output);
                }
            }
            byte[] outputBytes = cipher.doFinal();
            if (outputBytes != null) {
                outputStream.write(outputBytes);
            }
        }
        catch(Exception e) {
            System.out.println("Error AES256GCM_File_Decrypt: " + e);
        }finally {
            try {
                if (inputStream != null) {inputStream.close(); inputFile.delete();}
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Decrypt: " + e);
            }
            try {
                if (outputStream != null) outputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Decrypt: " + e);
            }
        }
    }

    /**
     * Cipher byte[] data to file using AES-256-GCM
     * @param key Key used to cipher data
     * @param data Data to cipher
     * @param outputPath Ciphered data file output path
     */
    void AES256GCMEncrypt(byte[] key, byte[] data, String outputPath){
        if(assertKeySize(key))
            return;
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        IvParameterSpec iv = generateIV();
        byte[] outByte;
        try {
            File outFile = new File(outputPath);
            outFile.createNewFile();
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secKey, parameterSpec);
            outByte = cipher.doFinal(data);

            FileOutputStream outputStream = new FileOutputStream(outputPath);
            outputStream.write(iv.getIV());
            outputStream.write(outByte);
            outputStream.close();
        }
        catch(Exception e){
            System.out.println("AES256_String_Encrypt Error : " + e);
        }
    }

    /**
     * Decipher file to data as byte[] using AES-256-GCM
     * @param key Key used to decipher data
     * @param inputPath Ciphered data file path
     * @return Data deciphered as byte[]
     */
    byte[] AES256GCMDecrypt(byte[] key, String inputPath){
        if(assertKeySize(key))
            return null;

        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        byte[] outByte = null;
        try {
            FileInputStream inputStream = new FileInputStream(inputPath);

            //Read first 16 byte to get iv
            byte[] ivBuffer = new byte[IVBITSIZE/8];
            int bytesRead;
            bytesRead = inputStream.read(ivBuffer);
            if(bytesRead < IVBITSIZE/8){
                System.out.println("Error : missing IV");
                return null;
            }
            IvParameterSpec iv = new IvParameterSpec(ivBuffer);
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.DECRYPT_MODE, secKey, parameterSpec);

            byte[] inputBytes = new byte[inputStream.available()];
            inputStream.read(inputBytes);

            inputStream.close();
            outByte = cipher.doFinal(inputBytes);
        }
        catch(Exception e){
            System.out.println("AES256_String_Encrypt Error : " + e);
        }
        return outByte;
    }

    /**
     * Cipher data as byte[] to byte[] using AES-256-GCM
     * @param key Key used to cipher data
     * @param data Input clear data as byte[]
     * @param iv IV used to cipher data
     * @return Ciphered data as byte[]
     */
    byte[] AES256GCMEncrypt(byte[] key, byte[] data, IvParameterSpec iv){
        if(assertKeySize(key))
            return null;

        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secKey, parameterSpec);
            ret = cipher.doFinal(data);
        }
        catch(Exception e){
            System.out.println("AES256_String_Encrypt Error : " + e);
        }
        return ret;
    }

    /**
     * Decipher data as byte[] to byte[] using AES-256-GCM
     * @param key Key used to decipher data
     * @param data Ciphered data to process
     * @param iv IV to use for processing
     * @return Clear data as byte[]
     */
    byte[] AES256GCMDecrypt(byte[] key, byte[] data, IvParameterSpec iv){
        if(assertKeySize(key))
            return null;

        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.DECRYPT_MODE, secKey, parameterSpec);
            ret = cipher.doFinal(data);
        }
        catch(Exception ignored){
        }
        return ret;
    }
}
