package vault.client;

import com.google.gson.Gson;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base32;

import javax.crypto.spec.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;

//TODO : file/folder creation exception handling
//TODO : Fonction writeObjToFile()

//TODO : Cipher dans des fichiers avec IV intégré prcq flemme
//TODO : file add / retrieve
//TODO : select company retrieve
//TODO : 1 obj client par connexion
//TODO : String to file pour envoyer clé master
//TODO : delete mk.json et upl.json after usage
//TODO : Delete file function
//TODO : Check path upload


public class Client {
    //Communication attribute
    private static String srv_name = "127.0.0.1";
    private static int srv_port = 8008;
    private static Socket clientSocket = null;
    private static BufferedWriter out = null;
    private static BufferedReader in = null;
    private static DataInputStream dataInputStream = null;
    private static DataOutputStream dataOutputStream = null;
    private static Scanner sc = null;

    //Utils attribute
    private static final CryptoUtils cry = new CryptoUtils();
    private static final Gson gson = new Gson();

    //Vault attribute
    private static VaultAttr vAttr = null;
    private static String companyName;
    private static final int NRECOVER = 2;

    //Vault attribute file
    private static final String workPath = ".\\data\\client\\";
    private static FileRegister fileRegister;
    private static final String registerFilename = "reg.json";
    private static final String userPointListFilename = "upl.json";
    private static final String masterKeyFilename = "mk.json";

    private static final String help = "select-company $companyName \t\t\t\t: Select $companyName vault - authentication required\n" +
            "ls \t\t\t\t\t\t\t\t\t\t\t: List files contained in current company vault\n" +
            "cat $filename\t\t\t\t\t\t\t\t: Print selected file\n" +
            "dl $filename $outpath\t\t\t\t\t\t: Download selected file to $outpath\n" +
            "upload $filename $path\t\t\t\t\t\t: Upload file as $filename from $path to vault\n" +
            "revoke-user $username\t\t\t\t\t\t: Revoke a user - authentication required [each members]\n" +
            "exit\t\t\t\t\t\t\t\t\t\t: Get out of current company's vault\n" +
            "new-company $companyName $nUser\t: Creat a new company name $companyName with $nUser and 2 to unlock vault - require each users to create a login/pwd\n" +
            "close \t\t\t\t\t\t\t\t\t\t: close vault.server connexion";

    public static void main(String[] args){
        try {
            clientSocket = new Socket(srv_name, srv_port);
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8));
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());
            sc = new Scanner(System.in);
            String usrInput;

            System.out.println("Welcome to CAA's vault vault.client ! Type 'help' to get available commands.");
            System.out.print("> ");

            //Create working directory
            new File(Client.workPath).mkdir();

            while ( (usrInput = sc.nextLine()) != null ) {
                if (usrInput.equalsIgnoreCase("close")) {
                    Client.cleanRoutine();
                    break;
                }
                process_input(usrInput);
                System.out.print((Client.companyName == null ? "" : Client.companyName) + "> ");
            }
            cleanRoutine();
            //Close connexion

        } catch (Exception ex) {
            System.out.println("Error : " + ex.toString());
        } finally {
            try {
                if (out != null) out.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex.toString());
            }
            try {
                if (in != null) in.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex.toString());
            }
            try {
                if (dataInputStream != null) dataInputStream.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex.toString());
            }
            try {
                if (dataOutputStream != null) dataOutputStream.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex.toString());
            }
            try {
                if (clientSocket != null && ! clientSocket.isClosed()) clientSocket.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex.toString());
            }
        }


        //Initiate connexion with vault.server

        /*select-company $companyName
        1) Check if company exists -> yes : continue - no : error
        2) Get ciphered master key
        3) Get user points
        4) Get file register (local copy)
        5) User authentication to generate "unlock_key"
        6) Get master_key
        7) Get file_register clear
        8) Delete working files
         */

        /*ls
        1) Display file_register
         */

        /*cat $filename
        1) Get file from vault.server
        2) Uncipher file
        3) Display file
        4) Delete working files
         */

        /*dl $filename $outpath
        1) Get file from vault.server
        2) Uncipher in -> outpath
        3) Delete working file
         */

        /*upload $filename $path
        1) Create file_key
        2) Create ciphered file
        3) Send file to srv
        4) Update file_register
        5) Create ciphered file_register
        6) Send file_register to srv
         */


        //test();
    }

    private static void cleanRoutine() throws IOException {
        //Delete working directory
        FileUtils.deleteDirectory(new File(Client.workPath));
    }

    private static void process_input(String input) throws Exception {
        String[] split_input = input.split("\\s+");
        System.out.println();

        switch (split_input[0].toLowerCase()){
            case "select-company" :
                if(split_input.length < 2){
                    System.out.println("Error : not enough argument");
                    break;
                }
                selectCompany(split_input[1]);
                break;
            case "help" :
                System.out.println(help);
                break;
            case "test" :
                test();
                break;
            case "ls" :
                if(Client.companyName != null)
                    printRegister();
                else
                    System.out.println("Error : you are not inside a company's vault");
                break;
            case "cat" :
                if(Client.companyName != null) {
                    if (split_input.length < 2)
                        System.out.println("Error : not enough argument");
                    else
                        printFile(split_input[1]);
                }
                else
                    System.out.println("Error : you are not inside a company's vault");
                break;
            case "dl" :
                break;
            case "upload" :
                if(Client.companyName != null) {
                    if (split_input.length < 3)
                        System.out.println("Error : not enough argument");
                    else
                        uploadFile(split_input[1], split_input[2]);
                }
                else
                    System.out.println("Error : you are not inside a company's vault");
                break;
            case "revoke-user" :
                if(Client.companyName != null)
                    revokeUser();
                else
                    System.out.println("Error : you are not inside a company's vault");
                break;
            case "new-company" :
                if(split_input.length < 3){
                    System.out.println("Error : not enough argument");
                    break;
                }
                newCompany(split_input[1], split_input[2]);
                break;
            case "exit" :
                if(Client.companyName != null)
                    exitCompany();
                else
                    System.out.println("Error : you are not inside a company's vault");
                break;
            case "close" :
                break;
            default :
                System.out.println("Error : unknown command ");
                break;
        }
    }

    private static void printFile(String filename) throws Exception {
        Client.receiveAndUncipher(filename);
        Thread.sleep(50);
        BufferedReader br = new BufferedReader(new FileReader(Client.generatePath(filename)));
        String line;
        while ((line = br.readLine()) != null) {
            System.out.println(line);
        }
        br.close();

        //delete files after usage
        File f = new File(Client.generatePath(filename));
        File c = new File(Client.generatePath(Client.generateCipheredFilename(filename)));
        f.delete();
        c.delete();
    }

    private static void uploadFile(String filename, String path) throws Exception {
        File src = new File(path);
        File dst = new File(Client.generatePath(filename));
        try {
            FileUtils.copyFile(src, dst);
        } catch (IOException e) {
            System.out.println("Error : can't get to source file");
            return;
        }

        cipherAndSend(filename);
        Client.fileRegister.files.add(filename);

        //Delete files (once sent)
        Thread.sleep(50);
        System.out.println("File " + filename + " uploaded !");
        File c = new File(Client.generatePath(Client.generateCipheredFilename(filename)));
        dst.delete();
        c.delete();
    }

    private static void revokeUser() throws Exception {
        if(Client.vAttr.nUsers <= Client.NRECOVER) {
            System.out.println("Not enough user to revoke one, you must register a new user. Please set new user amount");
            System.out.print("new nUser : ");
            Client.vAttr.nUsers = Integer.parseInt(sc.nextLine());
        }
        else
            Client.vAttr.nUsers--;
        System.out.println("Each remaining user must re-authenticate to revoke one user ... let's go");
        Client.initialUserAuth();
    }

    private static void printRegister() {
        for(String filename : Client.fileRegister.files){
            System.out.println(filename);
        }
    }

    private static void exitCompany() throws Exception {
        //Cipher + send fileRegister
        Client.writeObjToFile(Client.fileRegister, Client.registerFilename);

        Client.cipherAndSend(Client.registerFilename);

        //Delete company folder + Vault attribute (key, etc. ...)
        Client.cleanRoutine();
        Client.companyName = null;
        Client.vAttr = null;
        Client.fileRegister = null;
    }

    private static void cipherAndSend(String filename) throws Exception {
        Client.cry.AES256GCM_File_Encrypt(Client.cry.generateFileKey(Client.vAttr.masterKey, filename),
                Client.generatePath(filename),
                Client.generatePath(Client.generateCipheredFilename(filename)));

        Client.sendFile(Client.generateCipheredFilename(filename));
    }

    private static void receiveAndUncipher(String filename) throws Exception {
        Client.receiveFile(Client.generateCipheredFilename(filename));

        Client.cry.AES256GCM_File_Decrypt(
                Client.cry.generateFileKey(Client.vAttr.masterKey, filename),
                Client.generatePath(Client.generateCipheredFilename(filename)),
                Client.generatePath(filename)
        );
    }

    private static void newCompany(String companyName, String nUser) throws Exception {
        if(Client.companyName != null){
            System.out.println("Error : first exit current company's vault !");
            return;
        }
        int nUserInt = Integer.parseInt(nUser);
        if(nUserInt < Client.NRECOVER){
            System.out.println("Error : nUser should be bigger than " + Client.NRECOVER);
            return;
        }

        out.write("new-company " + companyName + "\n");
        out.flush();
        String srvInput = in.readLine();
        if(Objects.equals(srvInput, "error")){
            System.out.println("Error : company already exists or issue at company creation !");
            return;
        }
        Client.vAttr = new VaultAttr();
        Client.companyName = companyName;

        //Wokring dir init
        initCompanyFolder();

        //Master key generation
        Client.vAttr.masterKey = Client.cry.generateAESKey();

        System.out.println("Company " + Client.companyName + " created, require users initial authentication");

        //User authentication (sends master key + user points to srv)
        Client.vAttr.nUsers = nUserInt;
        initialUserAuth();

        //FileRegister initialisation
        Client.fileRegister = new FileRegister();
    }

    private static String generateCipheredFilename(String filename){return "cip-" + filename;}

    private static void writeObjToFile(Object obj, String filename) throws IOException {
        File f = new File(generatePath(filename));
        f.createNewFile();
        FileWriter fw = new FileWriter(f);
        fw.write(Client.gson.toJson(obj));
        fw.flush();
        fw.close();
    }

    private static <T> T getObjFromFile(String filename, Class<T> type) throws IOException {
        File f = new File(generatePath(filename));
        FileReader fr = new FileReader(f);
        T ret = Client.gson.fromJson(fr, type);
        fr.close();

        return ret;
    }

    private static void sendMasterKey() throws Exception {
        IvParameterSpec iv = Client.cry.generateIV();
        CipheredMasterKey cmk = new CipheredMasterKey(
                Base64.getEncoder().encodeToString(Client.cry.AES256GCM_String_Encrypt(Client.vAttr.unlockKey, Client.vAttr.masterKey, iv)),
                Base64.getEncoder().encodeToString(iv.getIV())
        );

        writeObjToFile(cmk, Client.masterKeyFilename);
        Client.sendFile(Client.masterKeyFilename);
    }

    private static void receiveMasterKey() throws Exception {
        Client.receiveFile(Client.masterKeyFilename);
        CipheredMasterKey cmk = getObjFromFile(Client.masterKeyFilename, CipheredMasterKey.class);

        Client.vAttr.masterKey = Client.cry.AES256GCM_String_Decrypt(
                Client.vAttr.unlockKey,
                Base64.getDecoder().decode(cmk.ciphered_key),
                new IvParameterSpec(Base64.getDecoder().decode(cmk.iv))
        );
    }

    private static void initCompanyFolder() throws IOException{
        File checkPath = new File(workPath + Client.companyName);
        if(!checkPath.exists()){
            if(!checkPath.mkdirs()){
                throw new IOException("Cannot create working directory !");
            }
        }
    }

    private static void initialUserAuth() throws Exception {
        String[] usernames = new String[Client.vAttr.nUsers];
        String[] passwords = new String[Client.vAttr.nUsers];

        //Unlock key generation
        Client.vAttr.unlockKey = Client.cry.generateAESKey();

        Map<Integer, byte[]> pointMap = Client.cry.generateShamirPoints(Client.vAttr.nUsers, Client.NRECOVER, Client.vAttr.unlockKey);
        CipheredUserPointList userPointList = new CipheredUserPointList(Client.vAttr.nUsers);

        for(int i = 0; i < Client.vAttr.nUsers; ++i){
            System.out.print("Username" + i + ">");
            usernames[i] = sc.nextLine();
            do {
                System.out.print("Password" + i + ">");
                passwords[i] = sc.nextLine();
                System.out.print("Confirm password" + i + ">");
            } while(!Objects.equals(sc.nextLine(), passwords[i]));

            IvParameterSpec iv = Client.cry.generateIV();
            userPointList.userPoints[i] = new CipheredUserPoint(
                    Base64.getEncoder().encodeToString(cry.sha256(usernames[i])),
                    Base64.getEncoder().encodeToString(Client.cry.AES256GCM_String_Encrypt(
                            Client.cry.sha256(passwords[i]),
                            pointMap.get(i+1),
                            iv
                    )),
                    Base64.getEncoder().encodeToString(iv.getIV())
            );
        }
        writeObjToFile(userPointList, Client.userPointListFilename);
        Client.sendFile(Client.userPointListFilename);

        //SINON LE FICHIER MASTER KEY NE S'ECRIT PAS LOL 2h POUR TROUVER
        Thread.sleep(50);

        sendMasterKey();
    }

    private static void generateKeys() {
        Client.vAttr.masterKey = Client.cry.generateAESKey();
        Client.vAttr.unlockKey = Client.cry.generateAESKey();
    }

    private static void selectCompany(String company_name) throws Exception {
        if(Client.companyName != null){
            System.out.println("Error : first exit current company's vault !");
            return;
        }
        String srv_input;

        //Select company vault server side
        out.write("select-company " + company_name + "\n");
        out.flush();
        srv_input = in.readLine();
        if(Objects.equals(srv_input, "error")){
            System.out.println("Error : no such company ! ");
            return;
        }

        Client.vAttr = new VaultAttr();
        Client.companyName = company_name;

        initCompanyFolder();

        //Get user points from srv
        receiveFile(Client.userPointListFilename);
        CipheredUserPointList userPointList = getObjFromFile(Client.userPointListFilename, CipheredUserPointList.class);

        //Recover unlock key
        recoverUnlockKey(userPointList);

        //Get master key from srv + uncipher
        receiveMasterKey();

        //TODO : get file register + uncipher
        Client.receiveAndUncipher(Client.registerFilename);
        Client.fileRegister = new FileRegister();
        Client.fileRegister = Client.getObjFromFile(Client.registerFilename, FileRegister.class);

        System.out.println("Vault unlocked");
    }

    private static void recoverUnlockKey(CipheredUserPointList userPointList) {

        Map<Integer, byte[]> pointMap = new HashMap<Integer, byte[]>();
        //Client.cry.generateShamirPoints(Client.nUsers, Client.nRecover, Client.unlockKey);

        String username;
        String password;
        String hashUsername;
        byte[] hashPassword;
        byte[] recoveredPoint;
        for(int i = 0; i < NRECOVER; ++i) {
            recoveredPoint = null;

            while(true) {
                //Get username + pwd
                System.out.print("Username " + i + ">");
                username = sc.nextLine();
                System.out.print("Password " + i + ">");
                password = sc.nextLine();

                hashUsername = Base64.getEncoder().encodeToString(Client.cry.sha256(username));
                hashPassword = Client.cry.sha256(password);

                //Check if there's a match in CipheredUserPointList.userPoints
                for (int j = 0; j < userPointList.userPoints.length; ++j) {
                    if (Objects.equals(userPointList.userPoints[j].username, hashUsername) && pointMap.get(j+1) == null) {
                        //If match, try to uncipher point with password hash
                        recoveredPoint = Client.cry.AES256GCM_String_Decrypt(
                                hashPassword,
                                Base64.getDecoder().decode(userPointList.userPoints[j].cipher_point),
                                new IvParameterSpec(Base64.getDecoder().decode(userPointList.userPoints[j].iv))
                        );
                        pointMap.put(j + 1, recoveredPoint);
                        break;
                    }
                }

                if (recoveredPoint == null) {
                    System.out.println("Error : no matching username, same user reused or bad password");
                } else {
                    break;
                }
            }
        }

        Client.vAttr.unlockKey = Client.cry.recover_unlock_key(userPointList.userPoints.length, Client.NRECOVER, pointMap);
    }

    private static String generatePath(String filename){ return Client.workPath + Client.companyName + "\\" + filename;}

    private static void sendFile(String filename) throws Exception{
        int bytes = 0;
        File file = new File(Client.generatePath(filename));
        FileInputStream fileInputStream = new FileInputStream(file);

        //Base32 used to avoir +, -, /, \ char
        out.write("receive-file " +
                Base32.toBase32String(Client.cry.sha256(filename)) +
                "\n");
        out.flush();

        // send file size
        dataOutputStream.writeLong(file.length());
        // break file into chunks
        byte[] buffer = new byte[4*1024];
        while ((bytes=fileInputStream.read(buffer))!=-1){
            dataOutputStream.write(buffer,0,bytes);
            dataOutputStream.flush();
        }
        fileInputStream.close();
    }

    private static void receiveFile(String filename) throws Exception{
        int bytes = 0;
        FileOutputStream fileOutputStream = new FileOutputStream(Client.generatePath(filename));

        //Base32 used to avoir +, -, /, \ char
        out.write("send-file " +
                Base32.toBase32String(Client.cry.sha256(filename)) +
                "\n");
        out.flush();

        long size = dataInputStream.readLong();     // read file size
        byte[] buffer = new byte[4*1024];
        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
            fileOutputStream.write(buffer,0,bytes);
            size -= bytes;      // read upto file size
        }
        fileOutputStream.close();
    }

    private static void test(){
        Client.fileRegister.files.add("coucou.txt");

        /*
        IvParameterSpec iv = cry.generateIV();
        byte[] pwd = cry.sha256("password1");
        CipheredUserPoint u1 = new CipheredUserPoint(Base64.getEncoder().encodeToString(cry.sha256("user1")),
                Base64.getEncoder().encodeToString(cry.AES256GCM_String_Encrypt(pwd, parts.get(1), iv)),
                Base64.getEncoder().encodeToString(iv.getIV()));

        iv = cry.generateIV();
        pwd = cry.sha256("password2");
        CipheredUserPoint u2 = new CipheredUserPoint(Base64.getEncoder().encodeToString(cry.sha256("user2")),
                Base64.getEncoder().encodeToString(cry.AES256GCM_String_Encrypt(pwd, parts.get(2), iv)),
                Base64.getEncoder().encodeToString(iv.getIV()));

        iv = cry.generateIV();
        pwd = cry.sha256("password3");
        CipheredUserPoint u3 = new CipheredUserPoint(Base64.getEncoder().encodeToString(cry.sha256("user3")),
                Base64.getEncoder().encodeToString(cry.AES256GCM_String_Encrypt(pwd, parts.get(3), iv)),
                Base64.getEncoder().encodeToString(iv.getIV()));

        iv = cry.generateIV();
        pwd = cry.sha256("password4");
        CipheredUserPoint u4 = new CipheredUserPoint(Base64.getEncoder().encodeToString(cry.sha256("user4")),
                Base64.getEncoder().encodeToString(cry.AES256GCM_String_Encrypt(pwd, parts.get(4), iv)),
                Base64.getEncoder().encodeToString(iv.getIV()));

        CipheredUserPointList upl = new CipheredUserPointList(4);
        upl.userPoints[0] = u1;
        upl.userPoints[1] = u2;
        upl.userPoints[2] = u3;
        upl.userPoints[3] = u4;

        System.out.println(gson.toJson(upl));

        System.out.println();
        System.out.println();
        System.out.println();

        iv = cry.generateIV();
        CipheredMasterKey cmk = new CipheredMasterKey(
                Base64.getEncoder().encodeToString(cry.AES256GCM_String_Encrypt(unlock_key, master_key, iv)),
                Base64.getEncoder().encodeToString(iv.getIV())
        );

        System.out.println(gson.toJson(cmk));
*/
        /*
        CryptoUtils cli = new CryptoUtils();
        byte[] master_key = cli.generate_master_key();

        System.out.println("Master key : " + Base64.getEncoder().encodeToString(master_key));

        Map<Integer, byte[]> parts = cli.generate_shamir_points(4, 2, master_key);

        for(int i : parts.keySet()){
            System.out.println("User " + i + ", value = " + Base64.getEncoder().encodeToString(parts.get(i)));
        }

        System.out.println();

        Map<Integer, byte[]> recover_parts = new HashMap<>();
        recover_parts.put(3, parts.get(3));
        recover_parts.put(4, parts.get(4));

        for(int i : recover_parts.keySet()){
            System.out.println("Reco - User " + i + ", value = " + Base64.getEncoder().encodeToString(recover_parts.get(i)));
        }

        byte[] master_key_recovered = cli.recover_unlock_key(4,2, recover_parts);
        System.out.println("Recovered master key : " + Base64.getEncoder().encodeToString(master_key_recovered));

        System.out.println();

        System.out.println("Hash 1 string 'hello' : " + Base64.getEncoder().encodeToString(cli.sha256("hello")));
        System.out.println("Hash 2 string 'hello' : " + Base64.getEncoder().encodeToString(cli.sha256("hello")));
        System.out.println("Hash 3 string 'coucou' : " + Base64.getEncoder().encodeToString(cli.sha256("coucou")));

        System.out.println();

        String stringcipher1 = "bonjour je m'appelle yvan lol !";
        String pwdcipher1 = "password123";

        System.out.println("String to cipher 1 : 'bonjour je m'appelle yvan lol !'");
        System.out.println("Password to cipher 1 : 'password123'");

        byte[] pwd_key = cli.sha256(pwdcipher1);
        System.out.println("Key from password 1 : " + Base64.getEncoder().encodeToString(pwd_key));

        IvParameterSpec iv1 = cli.generateIV();
        byte[] cipher1 = cli.AES256_String_Encrypt(pwd_key, stringcipher1.getBytes(StandardCharsets.UTF_8), iv1);
        System.out.println("Cipher from string 1 : " + Base64.getEncoder().encodeToString(cipher1));

        byte[] recovered_cipher1 = cli.AES256_String_Decrypt(pwd_key, cipher1, iv1);
        System.out.println("Recovered from cipher : " + new String(recovered_cipher1, StandardCharsets.UTF_8));

        File claire = new File(".\\data\\vault.client\\claire.txt");
        File cipher = new File(".\\data\\vault.client\\cipher.txt");
        File uncipher = new File(".\\data\\vault.client\\uncipher.txt");

        cli.AES256GCM_File_Encrypt(master_key, iv1, claire, cipher);
        cli.AES256GCM_File_Decrypt(master_key, iv1, cipher, uncipher);

        System.out.println();

        System.out.println("Key with filename 'coucou' " + Base64.getEncoder().encodeToString(cli.generate_file_key(master_key, "coucou")));
        System.out.println("Key with filename 'coucou' " + Base64.getEncoder().encodeToString(cli.generate_file_key(master_key, "coucou")));
        System.out.println("Key with filename 'caca' " + Base64.getEncoder().encodeToString(cli.generate_file_key(master_key, "caca")));
        System.out.println("Key with filename 'caca' " + Base64.getEncoder().encodeToString(cli.generate_file_key(master_key, "caca")));
    */
    }

}
