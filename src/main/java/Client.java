import utils.KeyGen;

import javax.crypto.SecretKey;
import java.lang.reflect.Array;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.ArrayList;

public class Client {

    String _clientId;
    PublicKey _address;
    PrivateKey _decrypt;
    ArrayList<Message> _sent = new ArrayList<>();
    ArrayList<Message> _receive = new ArrayList<>();


    public Client(String name, KeyPair keys){
        _clientId = name;
        _address = keys.getPublic();
        _decrypt = keys.getPrivate();
    }

    public Client(String name, KeyPair keys, ArrayList<Message> sentMsg, ArrayList<Message> receivedMsg){
        _clientId = name;
        _address = keys.getPublic();
        _decrypt = keys.getPrivate();
        _sent = sentMsg;
        _receive = receivedMsg;
    }

    public void displayClient(){
        System.out.println("Name: " + _clientId);
        System.out.println("address: " + _address.toString());
        System.out.println("decrypt Key: " + _decrypt.toString());
    }


    public void receiveMessage(Message msg){
        _receive.add(msg);
    }

    public PublicKey getPublicKey(){
        return _address;
    }

    public PrivateKey getPrivateKey(){
        return _decrypt;
    }

    //encrypt and send message
    public void sendMessage(String content, Client recipient) throws Exception {

        SecretKey encryptKey = KeyGen.generateAESKey();

        //message is encrypted
        String output = KeyGen.encryptAES(content, encryptKey);

        //encrypt key is hidden
        byte[] hiddenKey = KeyGen.encryptRSA(encryptKey.getEncoded(), recipient.getPublicKey());

        Message msg = new Message(recipient.getPublicKey(), output, hiddenKey);
        _sent.add(msg);
        recipient.receiveMessage(msg);
    }

    //getters and setters
    public void displaySent() throws Exception {
        for(int i = 0; i < _sent.size(); i++){
            _sent.get(i).displayMessage(_decrypt);
        }
    }

    public void displayReceived() throws Exception {
        for(int i = 0; i < _receive.size(); i++){
            _receive.get(i).displayMessage(_decrypt);
        }
    }

}
