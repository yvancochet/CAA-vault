package vault.client;

import com.google.gson.Gson;
import org.apache.commons.io.FileUtils;
import org.bouncycastle.util.encoders.Base32;

import javax.crypto.spec.*;
import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;


public class Client {
    //Communication attribute
    private static final String srv_name = "127.0.0.1";
    private static final int srv_port = 8008;
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
    private static final String masterKeyFilename = "mk";

    private static final String help = """
            select-company $companyName \t: Select $companyName vault - authentication required
            ls \t\t\t\t\t\t\t\t: List files contained in current company vault
            cat $filename\t\t\t\t\t: Print selected file
            dl $filename $outpath\t\t\t: Download selected $filename to $outpath /!\\ filename must not contain any space char || $outpath must be in between "" /!\\
            upload $filename "$path"\t\t: Upload file as $filename from $path to vault /!\\ filename must not contain any space char || $path must be in between "" /!\\
            delete $filename\t\t\t\t: delete $filename from vault
            revoke-user $username\t\t\t: Revoke a user - authentication required [each members]
            exit\t\t\t\t\t\t\t: Get out of current company's vault
            new-company $companyName $nUser\t: Creat a new company name $companyName with $nUser and 2 to unlock vault - require each users to create a login/pwd
            close \t\t\t\t\t\t\t: close vault.server connexion""";

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

            //Create work directory
            new File(Client.workPath).mkdirs();

            //Get and compute user input while != "close"
            while ( (usrInput = sc.nextLine()) != null ) {
                if (usrInput.equalsIgnoreCase("close")) {
                    break;
                }
                process_input(usrInput);
                System.out.print((Client.companyName == null ? "" : Client.companyName) + "> ");
            }
            //Close connexion and clean routine
        } catch (Exception ex) {
            System.out.println("Error : " + ex);
        } finally {
            try {
                if(Client.companyName != null)
                    Client.exitCompany();
                else
                    Client.cleanRoutine();
            } catch(Exception ex){
                System.out.println("Error : " + ex);
            }
            try {
                if (out != null) out.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex);
            }
            try {
                if (in != null) in.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex);
            }
            try {
                if (dataInputStream != null) dataInputStream.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex);
            }
            try {
                if (dataOutputStream != null) dataOutputStream.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex);
            }
            try {
                if (clientSocket != null && ! clientSocket.isClosed()) clientSocket.close();
            } catch (IOException ex) {
                System.out.println("Error : " + ex);
            }
        }
    }

    /**
     * Delete client working directory + content
     * @throws IOException IOException
     */
    private static void cleanRoutine() throws IOException {
        //Delete working directory
        FileUtils.deleteDirectory(new File(Client.workPath));
    }

    /**
     * Assert if a company is selected or not
     * @return company selected or not
     */
    private static boolean assertCompany(){
        if(Client.companyName == null){
            System.out.println("Error : you are not inside a company's vault");
            return false;
        }
        return true;
    }

    /**
     * Assert if user input matches number of parameter needed
     * @param required Required number of param
     * @param given Given number of param
     * @return enough param or not
     */
    private static boolean assertNParam(int required, int given){
        if(given < required){
            System.out.println("Error : not enough argument");
            return false;
        }
        return true;
    }

    /**
     * Process user input and call required functions
     * @param input user input
     * @throws Exception fileNotFound, IOException
     */
    private static void process_input(String input) throws Exception {
        String[] split_input = input.split("\\s+");
        System.out.println();

        switch (split_input[0].toLowerCase()){
            case "select-company" :
                if(assertNParam(2, split_input.length))
                    selectCompany(split_input[1]);
                break;
            case "help" :
                System.out.println(help);
                break;
            case "test" :
                test();
                break;
            case "ls" :
                if(Client.assertCompany())
                    printRegister();
                break;
            case "cat" :
                if(Client.assertCompany() && assertNParam(2, split_input.length))
                    printFile(split_input[1]);
                break;
            case "delete" :
                if(Client.assertCompany() && assertNParam(2, split_input.length))
                    deleteFile(split_input[1]);
                break;
            case "dl" :
                if(Client.assertCompany() && assertNParam(3, split_input.length))
                    try {
                        downloadFile(split_input[1], input.substring(input.indexOf("\"") + 1, input.lastIndexOf("\"")));
                    } catch(Exception e){
                        System.out.println("Error : bad input");
                    }
                break;
            case "upload" :
                if(Client.assertCompany() && assertNParam(3, split_input.length))
                    try {
                        uploadFile(split_input[1], input.substring(input.indexOf("\"") + 1, input.lastIndexOf("\"")));
                    } catch(Exception e){
                        System.out.println("Error : bad input");
                    }
                break;
            case "revoke-user" :
                if(Client.assertCompany())
                    revokeUser();
                break;
            case "new-company" :
                if(assertNParam(3, split_input.length))
                    newCompany(split_input[1], split_input[2]);
                break;
            case "exit" :
                if(assertCompany())
                    exitCompany();
                break;
            case "close" :
                break;
            default :
                System.out.println("Error : unknown command ");
                break;
        }
    }

    /**
     * Delete a file on server side
     * @param filename filename to delete
     * @throws IOException fileNotFound, IOException
     */
    private static void deleteFile(String filename) throws IOException {
        //Base32 used to avoid +, -, /, \ char
        out.write("delete-file " +
                Base32.toBase32String(Client.cry.sha256(Client.generateCipheredFilename(filename))) +
                "\n");
        out.flush();

        String srvResponse = in.readLine();
        if(Objects.equals(srvResponse, "ok"))
            System.out.println("File deleted successfully");
        else if(Objects.equals(srvResponse, "error"))
            System.out.println("Error : nu such file");

        Client.fileRegister.files.removeElement(filename);
    }

    /**
     * Download a file from server
     * @param filename file to download
     * @param outpath file output path
     * @throws Exception fileNotFound, IOException
     */
    private static void downloadFile(String filename, String outpath) throws Exception {
        Client.receiveAndUncipher(filename);
        File dst = new File(outpath);
        File src = new File(Client.generatePath(filename));

        FileUtils.copyFile(src, dst);
        src.delete();
    }

    /**
     * Print file from server
     * @param filename filename to print
     * @throws Exception fileNotFound, IOException
     */
    private static void printFile(String filename) throws Exception {
        Client.receiveAndUncipher(filename);
        Thread.sleep(50);
        BufferedReader br = new BufferedReader(new FileReader(Client.generatePath(filename), StandardCharsets.UTF_8));
        String line;

        PrintStream out = new PrintStream(System.out, true, StandardCharsets.UTF_8);
        while ((line = br.readLine()) != null) {
            out.println(line);
        }
        br.close();

        //delete files after usage
        File f = new File(Client.generatePath(filename));
        File c = new File(Client.generatePath(Client.generateCipheredFilename(filename)));
        f.delete();
        c.delete();
    }

    /**
     * Uplaod file to server
     * @param filename filename (srv side)
     * @param path source path
     * @throws Exception fileNotFound, IOException
     */
    private static void uploadFile(String filename, String path) throws Exception {
        File src = new File(path);
        File dst = new File(Client.generatePath(filename));
        if(!src.exists()){
            System.out.println("Error : cannot find specified file");
            return;
        }
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

    /**
     * Revoke a user
     * @throws Exception fileNotFound, IOException
     */
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

    /**
     * Print file register
     */
    private static void printRegister() {
        for(String filename : Client.fileRegister.files){
            System.out.println(filename);
        }
    }

    /**
     * Exit a company's vault
     * @throws Exception fileNotFound, IOException
     */
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

    /**
     * Cipher a file and send it to the server
     * @param filename name of the file to process
     * @throws Exception fileNotFound, IOException
     */
    private static void cipherAndSend(String filename) throws Exception {
        Client.cry.AES256GCMEncrypt(Client.cry.generateFileKey(Client.vAttr.masterKey, filename),
                Client.generatePath(filename),
                Client.generatePath(Client.generateCipheredFilename(filename)));

        Client.sendFile(Client.generateCipheredFilename(filename));
    }

    /**
     * Download a file from server and decipher it
     * @param filename name of the file to process
     * @throws Exception fileNotFound, IOException
     */
    private static void receiveAndUncipher(String filename) throws Exception {
        Client.receiveFile(Client.generateCipheredFilename(filename));

        Client.cry.AES256GCMDecrypt(
                Client.cry.generateFileKey(Client.vAttr.masterKey, filename),
                Client.generatePath(Client.generateCipheredFilename(filename)),
                Client.generatePath(filename)
        );

        (new File(Client.generateCipheredFilename(filename))).delete();
    }

    /**
     * Create a new company (vault)
     * @param companyName name of the company
     * @param nUser number of user to authenticate
     * @throws Exception fileNotFound, IOException
     */
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

    /**
     * Generate ciphered filename (different from clear filename)
     * @param filename clear filename
     * @return filename with "cip-" added in front
     */
    private static String generateCipheredFilename(String filename){return "cip-" + filename;}

    /**
     * Writes an object to a file using Google gson library
     * @param obj Object to process
     * @param filename Output filename
     * @throws IOException IOException
     */
    private static void writeObjToFile(Object obj, String filename) throws IOException {
        File f = new File(generatePath(filename));
        f.createNewFile();
        FileWriter fw = new FileWriter(f);
        fw.write(Client.gson.toJson(obj));
        fw.flush();
        fw.close();
    }

    /**
     * Get an object from a json file using Google gson library
     * @param filename name of the file to process
     * @param type Type of the object to creat
     * @param <T> Type
     * @return Created object
     * @throws IOException IOException
     */
    private static <T> T getObjFromFile(String filename, Class<T> type) throws IOException {
        File f = new File(generatePath(filename));
        FileReader fr = new FileReader(f);
        T ret = Client.gson.fromJson(fr, type);
        fr.close();

        return ret;
    }

    /**
     * Sends master key to server (ciphered master key)
     * @throws Exception fileNotFound, IOException
     */
    private static void sendMasterKey() throws Exception {
        Client.cry.AES256GCMEncrypt(
                Client.vAttr.unlockKey,
                Client.vAttr.masterKey,
                Client.generatePath(Client.masterKeyFilename));

        Client.sendFile(Client.masterKeyFilename);
    }

    /**
     * Receive master key from server (ciphered) and decipher it
     * @throws Exception fileNotFound, IOException
     */
    private static void receiveMasterKey() throws Exception {
        Client.receiveFile(Client.masterKeyFilename);
        Client.vAttr.masterKey = Client.cry.AES256GCMDecrypt(Client.vAttr.unlockKey, Client.generatePath(masterKeyFilename));
    }

    /**
     * Create current company working folder on client side
     * @throws IOException IOException
     */
    private static void initCompanyFolder() throws IOException{
        File checkPath = new File(workPath + Client.companyName);
        if(!checkPath.exists()){
            if(!checkPath.mkdirs()){
                throw new IOException("Cannot create working directory !");
            }
        }
    }

    /**
     * Process to initial user authentication (called at company creation or user revoke)
     * Each user must provide with a username / password
     * The generated shares are then sent to the server as well as the ciphered master key
     * @throws Exception fileNotFound, IOException
     */
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
            boolean passwordMismatch = false;
            do {
                System.out.print("Password" + i + ">");
                passwords[i] = sc.nextLine();
                System.out.print("Confirm password" + i + ">");
                passwordMismatch = !Objects.equals(sc.nextLine(), passwords[i]);
                if(passwordMismatch)
                    System.out.println("Error : password missmatch, please try again.");
            } while(passwordMismatch);

            IvParameterSpec iv = Client.cry.generateIV();
            userPointList.userPoints[i] = new CipheredUserPoint(
                    Base64.getEncoder().encodeToString(cry.sha256(usernames[i])),
                    Base64.getEncoder().encodeToString(Client.cry.AES256GCMEncrypt(
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

    /**
     * Select a company
     * -> Sends select-company command to server
     * -> Init company folder (client side)
     * -> Receive shamir shared
     * -> Process with user authentication
     * -> Receive and decipher master key
     * @param company_name name of the company to process
     * @throws Exception fileNotFound, IOException
     */
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
        (new File(Client.generatePath(Client.userPointListFilename))).delete();

        //Recover unlock key
        recoverUnlockKey(userPointList);

        //Get master key from srv + uncipher
        receiveMasterKey();

        Client.receiveAndUncipher(Client.registerFilename);
        Client.fileRegister = new FileRegister();
        Client.fileRegister = Client.getObjFromFile(Client.registerFilename, FileRegister.class);
        (new File(Client.generatePath(Client.registerFilename))).delete();

        System.out.println("Vault unlocked");
    }

    /**
     * Authenticate users and recover unlock key from shamir shares
     * @param userPointList List of ciphered userPoint(share)/username
     */
    private static void recoverUnlockKey(CipheredUserPointList userPointList) {

        Map<Integer, byte[]> pointMap = new HashMap<>();
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
                        recoveredPoint = Client.cry.AES256GCMDecrypt(
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

        Client.vAttr.unlockKey = Client.cry.recoverUnlockKey(userPointList.userPoints.length, Client.NRECOVER, pointMap);
    }

    /**
     * Generate path from a filename (adding workingPath in front)
     * @param filename Name of the file to process
     * @return generated path
     */
    private static String generatePath(String filename){ return Client.workPath + Client.companyName + "\\" + filename;}

    /**
     * Send a file to the server
     * @param filename file to send
     * @throws Exception fileNotFound, IOException
     */
    private static void sendFile(String filename) throws Exception{
        int bytes;
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
        file.delete();
    }

    /**
     * Receive a file from the server
     * @param filename file to receive
     * @throws Exception fileNotFound, IOException
     */
    private static void receiveFile(String filename) throws Exception{
        int bytes;
        FileOutputStream fileOutputStream = new FileOutputStream(Client.generatePath(filename));

        //Base32 used to avoid +, -, /, \ char
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

    /**
     * Used for test purposes
     */
    private static void test(){
    }

}
