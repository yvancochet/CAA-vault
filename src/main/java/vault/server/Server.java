package vault.server;

import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;


public class Server {
    private static final int srv_port = 8008;
    private static Socket clientSocket = null;
    private static BufferedReader in = null;
    private static BufferedWriter out = null;
    private static DataInputStream dataInputStream = null;
    private static DataOutputStream dataOutputStream = null;
    private static String companyName = null;
    private static final String workPath = ".\\data\\server\\";


    public static void main(String[] args){
        ServerSocket serverSocket;
        try {
            serverSocket = new ServerSocket(srv_port);
        } catch (IOException ex) {
            System.out.println("Error : " + ex);
            return;
        }
        while(true) {
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
                    processInput(input);
                }

            } catch (Exception ex) {
                System.out.println("Error : " + ex);
            } finally {
                if (in != null) {
                    try {
                        in.close();
                    } catch (IOException ex1) {
                        System.out.println("Error : " + ex1);
                    }
                }
                if (dataInputStream != null) {
                    try {
                        dataInputStream.close();
                    } catch (IOException ex1) {
                        System.out.println("Error : " + ex1);
                    }
                }
                if (dataOutputStream != null) {
                    try {
                        dataOutputStream.close();
                    } catch (IOException ex1) {
                        System.out.println("Error : " + ex1);
                    }
                }
                if (out != null) {
                    try {
                        out.close();
                    } catch (IOException ex1) {
                        System.out.println("Error : " + ex1);
                    }
                }
                if (clientSocket != null) {
                    try {
                        clientSocket.close();
                    } catch (IOException ex1) {
                        System.out.println("Error : " + ex1);
                    }
                }
            }
        }
    }

    private static void processInput(String input) throws Exception {
        String[] split_input = input.split("\\s+");
        System.out.println();

        if(split_input.length < 1){
            System.out.println("Error : unknown command ");
            return;
        }

        switch (split_input[0].toLowerCase()) {
            case "new-company" -> newCompany(split_input[1]);
            case "select-company" -> selectCompany(split_input[1]);
            case "receive-file" -> receiveFile(split_input[1]);
            case "send-file" -> sendFile(split_input[1]);
            case "delete-file" -> deleteFile(split_input[1]);
            default -> System.out.println("Error : unknown command ");
        }
    }

    private static void deleteFile(String filename) throws IOException {
        if((new File(Server.generatePath(filename))).delete())
            out.write("ok\n");
        else
            out.write("error\n");
        out.flush();
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
        int bytes;
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
        int bytes;
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
