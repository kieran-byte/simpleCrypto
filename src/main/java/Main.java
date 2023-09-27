import utils.KeyGen;

import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.ArrayList;

public class Main {



    public static void main(String args[]) throws Exception {


//        KeyPair pair = KeyGen.keyGen();
//
//        SecretKey key = KeyGen.generateAESKey();
//        System.out.println(key);
//
//        byte[] output = KeyGen.encryptRSA(key.toString(), pair.getPublic());
//        System.out.println(output.toString());
//
//        byte[] val = KeyGen.decryptRSA(output, pair.getPrivate());
//        String decryptedMessage = new String(val, "UTF-8");
//        System.out.println(decryptedMessage);


        //liam settup
        KeyPair liamKeys = KeyGen.keyGen();
        KeyPair bobKeys = KeyGen.keyGen();


        Client liam = new Client("liam", liamKeys);
        Client bob = new Client("bob", bobKeys);


        //auigsdgfauigsdgf
        liam.sendMessage("hello world", bob);
        Message sent = liam._sent.get(0);

        liam._sent.get(0).displayMessage(bobKeys.getPrivate());




    }

}
