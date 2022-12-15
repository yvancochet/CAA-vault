package vault.server;

import com.google.gson.Gson;
import vault.client.Client;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

public class Server {
    private static int srv_port = 8008;
    private static ServerSocket serverSocket;
    private static Socket clientSocket = null;
    private static BufferedReader in = null;
    private static BufferedWriter out = null;
    private static DataInputStream dataInputStream = null;
    private static DataOutputStream dataOutputStream = null;
    private static final Gson gson = new Gson();
    private static String companyName = null;
    private static final String workPath = ".\\data\\server\\";


    public static void main(String[] args){
        try {
            serverSocket = new ServerSocket(srv_port);
        } catch (IOException ex) {
            System.out.println("Error : " + ex.toString());
            return;
        }

        try {
            clientSocket = serverSocket.accept();
            in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream(), StandardCharsets.UTF_8));
            out = new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream(), StandardCharsets.UTF_8));
            dataInputStream = new DataInputStream(clientSocket.getInputStream());
            dataOutputStream = new DataOutputStream(clientSocket.getOutputStream());

            String input;
            while ((input = in.readLine()) != null) {
                if (input.equalsIgnoreCase("close")) {
                    break;
                }
                process_input(input);
            }
            clientSocket.close();
            in.close();
            out.close();
        } catch (Exception ex) {
            if (in != null) {
                try {
                    in.close();
                } catch (IOException ex1) {
                    System.out.println("Error : " + ex1.toString());
                }
            }
            if (dataInputStream != null) {
                try {
                    dataInputStream.close();
                } catch (IOException ex1) {
                    System.out.println("Error : " + ex1.toString());
                }
            }
            if (dataOutputStream != null) {
                try {
                    dataOutputStream.close();
                } catch (IOException ex1) {
                    System.out.println("Error : " + ex1.toString());
                }
            }
            if (out != null) {
                try {
                    out.close();
                } catch (IOException ex1) {
                    System.out.println("Error : " + ex1.toString());
                }
            }
            if (clientSocket != null) {
                try {
                    clientSocket.close();
                } catch (IOException ex1) {
                    System.out.println("Error : " + ex1.toString());
                }
            }
            System.out.println("Error : " + ex.toString());
        }
    }

    private static void process_input(String input) throws Exception {
        String[] split_input = input.split("\\s+");
        System.out.println();

        if(split_input.length < 1){
            System.out.println("Error : unknown command ");
            return;
        }

        switch (split_input[0].toLowerCase()){
            case "new-company" :
                newCompany(split_input[1]);
                break;
            case "select-company" :
                selectCompany(split_input[1]);
                break;
            case "receive-file" :
                receiveFile(split_input[1]);
                break;
            case "send-file" :
                sendFile(split_input[1]);
                break;
            case "read-master-key.json" :
                sendMasterKey();
                break;
            case "read-userpoints" :
                sendUserPoints();
                break;
            case "read-nrecover" :
                break;
            case "dl" :
                break;
            case "upload" :
                break;
            case "revoke-user" :
                break;
            case "exit" :
                break;
            case "close" :
                break;
            default :
                System.out.println("Error : unknown command ");
                break;
        }
    }

    private static void newCompany(String companyName) throws IOException {
        File checkPath = new File(Server.workPath + companyName);
        if(checkPath.exists()){
            out.write("error\n");
            out.flush();
            return;
        }
        if(!checkPath.mkdirs()) {
            out.write("error\n");
            out.flush();
            return;
        }
        Server.companyName = companyName;
        out.write("ok\n");
        out.flush();
    }

    private static void sendMasterKey() throws IOException {
        String masterKeyJson = Files.readString(Path.of(Server.workPath + companyName + "\\master-key.json"));
        out.write(masterKeyJson + "\n");
    }

    private static void sendUserPoints() throws IOException {
        String userPointsJson = Files.readString(Path.of(Server.workPath + companyName + "\\user-points.json"));
        out.write(userPointsJson + "\n");
    }

    private static void selectCompany(String companyName) throws IOException {
        File checkPath = new File(Server.workPath + companyName);
        if(!checkPath.exists()){
            out.write("error\n");
            out.flush();
            return;
        }
        Server.companyName = companyName;
        out.write("ok\n");
        out.flush();
    }

    private static String generatePath(String filename){ return Server.workPath + Server.companyName + "\\" +filename;}

    private static void sendFile(String filename) throws Exception{
        int bytes = 0;
        File file = new File(Server.generatePath(filename));
        FileInputStream fileInputStream = new FileInputStream(generatePath(filename));

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
        FileOutputStream fileOutputStream = new FileOutputStream(generatePath(filename));

        long size = dataInputStream.readLong();     // read file size
        byte[] buffer = new byte[4*1024];
        while (size > 0 && (bytes = dataInputStream.read(buffer, 0, (int)Math.min(buffer.length, size))) != -1) {
            fileOutputStream.write(buffer,0,bytes);
            size -= bytes;      // read upto file size
        }
        fileOutputStream.close();
    }

}
