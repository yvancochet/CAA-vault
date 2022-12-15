package vault.client;

import at.favre.lib.crypto.HKDF;
import com.codahale.shamir.Scheme;
import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.*;

//TODO : assert key size function
//TODO : function name without __
//TODO : planter des constantes si possible


class CryptoUtils {
    private final int KEYBITSIZE = 256;
    private final int IVBITSIZE = 128;
    private final int TAGSIZE = 128;

    private byte[] aes_key_generator(int key_bit_size){
        KeyGenerator keyGenerator = null;
        try {
            keyGenerator = KeyGenerator.getInstance("AES");
        }
        catch(Exception e){
            System.out.println("Error aes_key_generator : " + e.toString());
            return null;
        }
        keyGenerator.init(key_bit_size);
        SecretKey key = keyGenerator.generateKey();
        return key.getEncoded();
        /*
        SecureRandom random = new SecureRandom();
        byte[] keyBytes = new byte[key_byte_size];
        random.nextBytes(keyBytes);
        return (new SecretKeySpec(keyBytes, "AES")).getEncoded();
         */
    }

    byte[] generateAESKey(){
        return aes_key_generator(KEYBITSIZE);
    }

    /*
    private byte[] generate_key_from_pwd(String pwd){
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[16];
        random.nextBytes(salt);

        byte[] key = null;

        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
            KeySpec spec = new PBEKeySpec(pwd.toCharArray(), salt, 65536, 256);
            SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
            key = secret.getEncoded();
        }
        catch(Exception e){
            System.out.println("Error generate_key_from_pwd : " + e.toString());
        }

        return key;
    }
    */

    byte[] recover_unlock_key(int nb_points, int nb_points_to_recover, Map<Integer, byte[]> parts){
        if(parts.size() < nb_points_to_recover){
            System.out.println("Error : not enough points to recover unlock_key");
            return null;
        }

        Scheme scheme = new Scheme(new SecureRandom(), nb_points, nb_points_to_recover);
        return scheme.join(parts);
    }

    byte[] generateFileKey(byte[] master_key, String filename){
        HKDF hkdf = HKDF.fromHmacSha256();
        byte[] pseudoRandomKey = hkdf.extract(master_key, filename.getBytes(StandardCharsets.UTF_8));
        byte[] expandedAesKey = hkdf.expand(pseudoRandomKey, "aes-key".getBytes(StandardCharsets.UTF_8), 32);
        return new SecretKeySpec(expandedAesKey, "AES").getEncoded(); //AES-256 key
    }

    Map<Integer, byte[]> generateShamirPoints(int nb_points, int nb_points_to_recover, byte[] secret){
        Scheme scheme = new Scheme(new SecureRandom(), nb_points, nb_points_to_recover);
        return scheme.split(secret);
    }

    byte[] sha256(String str){
        MessageDigest sha = null;
        try {
            sha = MessageDigest.getInstance("SHA-256");
        }
        catch(Exception e){
            System.out.println("Error sha256 : " + e.toString());
            return null;
        }
        sha.update(str.getBytes(StandardCharsets.UTF_8));
        return sha.digest();
    }

    IvParameterSpec generateIV() {
        byte[] iv = new byte[IVBITSIZE/8];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    int AES256GCM_File_Encrypt(byte[] key, String inputPath, String outputPath){
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        if(key.length != KEYBITSIZE /8){
            System.out.println("Error : key size doesn't match requirement [256 bit]");
            return -1;
        }
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        IvParameterSpec iv = generateIV();
        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secKey, parameterSpec);
        }
        catch(Exception e){
            System.out.println("AES256GCM_File_Encrypt encryption error : " + e.toString());
            return -1;
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
            System.out.println("Error AES256GCM_File_Encrypt: " + e.toString());
        }finally {
            try {
                if (inputStream != null) inputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Encrypt: " + e.toString());
            }
            try {
                if (outputStream != null) outputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Encrypt: " + e.toString());
            }
        }
        return 0;
    }

    int AES256GCM_File_Decrypt(byte[] key, String inputPath, String outputPath){
        File inputFile = new File(inputPath);
        File outputFile = new File(outputPath);
        if(key.length != KEYBITSIZE /8){
            System.out.println("Error : key size doesn't match requirement [256 bit]");
            return -1;
        }
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        Cipher cipher = null;

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
                return -1;
            }
            IvParameterSpec iv = new IvParameterSpec(ivBuffer);

            try {
                cipher = Cipher.getInstance("AES/GCM/NoPadding");
                GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
                cipher.init(Cipher.DECRYPT_MODE, secKey, parameterSpec);
            }
            catch(Exception e){
                System.out.println("AES256GCM_File_Decrypt decryption error : " + e.toString());
                return -1;
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
            System.out.println("Error AES256GCM_File_Decrypt: " + e.toString());
        }finally {
            try {
                if (inputStream != null) inputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Decrypt: " + e.toString());
            }
            try {
                if (outputStream != null) outputStream.close();
            } catch (Exception e) {
                System.out.println("Error AES256GCM_File_Decrypt: " + e.toString());
            }
        }
        return 0;
    }

    byte[] AES256GCM_String_Encrypt(byte[] key, byte[] data, IvParameterSpec iv){
        if(key.length != KEYBITSIZE /8){
            System.out.println("Error : key size doesn't match requirement [256 bit]");
            return null;
        }
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.ENCRYPT_MODE, secKey, parameterSpec);
            ret = cipher.doFinal(data);
        }
        catch(Exception e){
            System.out.println("AES256_String_Encrypt Error : " + e.toString());
        }
        return ret;
    }

    byte[] AES256GCM_String_Decrypt(byte[] key, byte[] data, IvParameterSpec iv){
        if(key.length != KEYBITSIZE /8){
            System.out.println("Error : key size doesn't match requirement [256 bit]");
            return null;
        }
        SecretKey secKey = new SecretKeySpec(key, 0, key.length, "AES");
        byte[] ret = null;
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            GCMParameterSpec parameterSpec = new GCMParameterSpec(TAGSIZE, iv.getIV());
            cipher.init(Cipher.DECRYPT_MODE, secKey, parameterSpec);
            ret = cipher.doFinal(data);
        }
        catch(Exception e){
            System.out.println("AES256_String_Decrypt Error : " + e.toString());
        }
        return ret;
    }
}
