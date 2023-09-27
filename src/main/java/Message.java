import utils.KeyGen;

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

public class Message {
    private PublicKey _publicKey;
    private String _content;
    private byte[] _contentKey;

    // Constructor to create a message with a public key and content
    public Message(PublicKey publicKey, String content, byte[] contentKey) throws Exception {
        _publicKey = publicKey;
        _content = content;
        _contentKey = contentKey;
    }


    // decrpt message content then display
    public void displayMessage(PrivateKey decrypt) throws Exception {

        byte[] output = KeyGen.decryptRSA(_contentKey, decrypt);
        SecretKey secKey = new SecretKeySpec(output, "AES");

        String content = KeyGen.decryptAES(_content.toString(), secKey);
        System.out.println(content);
    }
}