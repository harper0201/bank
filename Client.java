import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Base64;

public class Client{
    public static final String PUBLIC_KEY_FILE = "Put";

    public static void main(String[] args) throws Exception {
        //get the localhost IP address, if server is running on some other IP, you need to use that
        Socket socket = null;
        ObjectOutputStream out = null;
        ObjectInputStream in = null;
        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));

        for(int i=0; i<5;i++){

            //establish socket connection to server
            String ip = args[0];
            int port = Integer.parseInt(args[1]);
            socket = new Socket(ip, port);
            out = new ObjectOutputStream(socket.getOutputStream());
            in = new ObjectInputStream(socket.getInputStream());
            //generate AES key
            generateAESkey AES = new generateAESkey();
            generateRSAKey RAS = new generateRSAKey();
            AES.generatekey();
            System.out.println("Get the public key");
            PublicKey publicKey = RAS.getPublicKey();
            System.out.println("public key: " + publicKey);
            //converting public key to byte
            byte[] byte_pubkey = AES.getSecretKey().getEncoded();

            //converting byte to String
            String str_key = Base64.getEncoder().encodeToString(byte_pubkey);
            System.out.println(AES.key);
            System.out.println(byte_pubkey);
            System.out.println(str_key);
            String epart1 = Base64.getEncoder().encodeToString(RAS.encrypt(str_key,publicKey));
            System.out.println("encrypt1: " + epart1);

            System.out.println("ID: ");
            String username = br.readLine();
            System.out.println("password: ");
            String password = br.readLine();
            String hash = (Hash(password));
            System.out.println(username + " " + hash);
            String epart2 = Base64.getEncoder().encodeToString(AES.encrypt(username + " " + password, AES.getSecretKey()));
            System.out.println("secret key: " + AES.getSecretKey());
            System.out.println("encrypt2: " + epart2);
            out.writeObject(epart1 + " " + epart2);
            //read the server response message
            String result = (String) in.readObject();
            System.out.println(result);
            while (result.equals("0")){
                System.out.println("The user info is incorrect");
                System.out.println("ID: ");
                username = br.readLine();
                System.out.println("password: ");
                password = br.readLine();
                hash = (Hash(password));
                out.writeObject(username + " " + hash);
                result = (String)in.readObject();
                System.out.println("**" + result);
            }
            if (result.equals("1")){
                String line = " ";
                BufferedReader br2 = new BufferedReader(new FileReader("balance.txt"));
                int balance = 0;
                while ((line = br2.readLine()) != null) {
                    String ans[] = line.split(" ");
                    if (ans[0].equals(username)) {
                        balance = Integer.parseInt(ans[1]);
                        break;
                    }
                }
                System.out.println("You account balance is " +  balance + ". Please select one of the following actions");
                System.out.println("1.Transfer");
                System.out.println("2.Exit");
                BufferedReader br3 = new BufferedReader(new InputStreamReader(System.in));
                String choice = br3.readLine();
                if(choice.equals("1")){
                    System.out.println("Enter the ID to which the money is transferred");
                    String receiver = br3.readLine();
                    System.out.println("Enter the money you want to transfer");
                    String money = br3.readLine();
                    out.writeObject(choice + " " + receiver + " " + money);
                }
                else{
                    out.writeObject("Exit");
                }
            }
            //close resources
            in.close();
            out.close();
            Thread.sleep(100);
        }
    }

    // https://howtodoinjava.com/java/java-security/how-to-generate-secure-password-hash-md5-sha-pbkdf2-bcrypt-examples/
    // How to get hashed password in java
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
