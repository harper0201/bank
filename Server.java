import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.lang.ClassNotFoundException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class Server{

    //static ServerSocket variable
    private static ServerSocket server;
    private static final String RSA  = "RSA";
    public static final String PRIVATE_KEY_FILE = "Prt";	//values changed fr each key
    public static final String PUBLIC_KEY_FILE = "Put";

    private static final char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static void main(String args[]) throws Exception {
        //create the socket server object
        int port = Integer.parseInt(args[0]);
        server = new ServerSocket(port);
        //keep listens indefinitely until receives 'exit' call or program terminates
        String message = "";


        while (true) {
            //creating socket and waiting for client connection
            Socket socket = server.accept();
            //read from socket to ObjectInputStream object
            ObjectInputStream in = new ObjectInputStream(socket.getInputStream());
            ObjectOutputStream out = new ObjectOutputStream(socket.getOutputStream());

            boolean result = false;
            BufferedReader br = new BufferedReader(new FileReader("passwd.txt"));
            String line = " ";
            while (result == false){
                message = (String) in.readObject();
                System.out.println("Message Received: " + message);
                String[] info = message.split(" ");
                String epart1 = info[0];
                String epart2 = info[1];
                System.out.println("epart1: " + epart1);
                System.out.println("epart2: " + epart2);
                generateRSAKey RSA = new generateRSAKey();
                generateAESkey AES = new generateAESkey();
                //converting string to Bytes
                byte[] bytePart1 = Base64.getDecoder().decode(epart1);
                //converting it back to public key

                String dpart1 = RSA.decrypt(bytePart1, RSA.getPrivateKey());
                System.out.println("Key in String: " + dpart1);

                byte[] bytePart2 = Base64.getDecoder().decode(dpart1);
                SecretKey originalKey = new SecretKeySpec(bytePart2, 0, bytePart2.length, "AES");
                System.out.println(bytePart2);
                //AES.generatekey(bytePart2);
                AES.secretKey = originalKey;
                System.out.println("Secret key: " + AES.getSecretKey());
                String dpart2 = AES.decrypt(Base64.getDecoder().decode(epart2),AES.getSecretKey());

                System.out.println("username + password " + dpart2);
                String[] parts = dpart2.split(" ");
                String username = parts[0];
                String password = parts[1];
                String hash = (Hash(password));
                System.out.println(username + " " + hash);
                while ((line = br.readLine()) != null) {
                    String ans[] = line.split(" ");
                    if (ans[0].equals(username) && ans[1].equals(hash)) {
                        result = true;
                        break;
                    }
                }
                if (result) {out.writeObject("1");}
                else{
                    out.writeObject("0");
                    br.close();
                    br = new BufferedReader(new FileReader("passwd.txt"));
                }
            }
            String message2 = (String)in.readObject();
            String[] parts2 = message2.split(" ");
            String choice = parts2[0];
            if (choice.equals("2")) break;
            else
            {
                String receiver = parts2[1];
                String money = parts2[2];
                BufferedReader br2 = new BufferedReader(new FileReader("balance.txt"));
                List<String> lines = new ArrayList<String>();
                String line2 = " ";
                while ((line2 = br2.readLine()) != null) {
                    String ans[] = line2.split(" ");
                    if (ans[0].equals(receiver)) {
                        int newBalance = Integer.parseInt(ans[1]) >= Integer.parseInt(money) ? Integer.parseInt(ans[1]) - Integer.parseInt(money) : -1;
                        if (newBalance == -1) out.writeObject(0);
                        else {
                            out.writeObject(1);
                            line2 = line2.replace(ans[1], String.valueOf(newBalance));
                            line2
                        }
                    }
                }

            }
            //create ObjectOutputStream object
            //write object to Socket
            //close resources
            in.close();
            out.close();
            socket.close();
            //terminate the server if client sends exit request
            if (message.equalsIgnoreCase("exit")) break;
        }
        System.out.println("Shutting down Socket server!!");
        //close the ServerSocket object
        server.close();
    }

    public static KeyPair generateRSAKkeyPair() throws Exception
    {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static String Hash(String password) throws NoSuchAlgorithmException {
        String generatedPassword = null;
        try
        {
            // Create MessageDigest instance for MD5
            MessageDigest md = MessageDigest.getInstance("MD5");

            // Add password bytes to digest
            md.update(password.getBytes());

            // Get the hash's bytes
            byte[] bytes = md.digest();

            // This bytes[] has bytes in decimal format. Convert it to hexadecimal format
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < bytes.length; i++) {
                sb.append(Integer.toString((bytes[i] & 0xff) + 0x100, 16).substring(1));
            }

            // Get complete hashed password in hex format
            generatedPassword = sb.toString();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return generatedPassword;
    }
}