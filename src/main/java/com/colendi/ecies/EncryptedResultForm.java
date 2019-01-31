package com.colendi.ecies;

public class EncryptedResultForm extends EncryptedResult {

    public EncryptedResultForm() {}

    public EncryptedResultForm(String ephemPublicKey, String iv, String mac, String ciphertext, String privateKey) {
        super(ephemPublicKey, iv, mac, ciphertext);
        this.privateKey = privateKey;
    }

    private String privateKey;


    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    @Override
    public String toString() {
        return "EncryptedResultForm{" +
                "privateKey='" + privateKey + '\'' +
                ", ephemPublicKey='" + ephemPublicKey + '\'' +
                ", iv='" + iv + '\'' +
                ", mac='" + mac + '\'' +
                ", ciphertext='" + ciphertext + '\'' +
                '}';
    }
}
