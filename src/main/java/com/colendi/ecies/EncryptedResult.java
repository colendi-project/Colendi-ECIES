package com.colendi.ecies;

public class EncryptedResult {

    public EncryptedResult(String privateKey, String ephemPublicKey, String iv, String mac, String ciphertext) {
        this.privateKey = privateKey;
        this.ephemPublicKey = ephemPublicKey;
        this.iv = iv;
        this.mac = mac;
        this.ciphertext = ciphertext;
    }

    private String privateKey;
    private String ephemPublicKey;
    private String iv;
    private String mac;
    private String ciphertext;

    public String getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(String privateKey) {
        this.privateKey = privateKey;
    }

    public String getEphemPublicKey() {
        return ephemPublicKey;
    }

    public void setEphemPublicKey(String ephemPublicKey) {
        this.ephemPublicKey = ephemPublicKey;
    }

    public String getIv() {
        return iv;
    }

    public void setIv(String iv) {
        this.iv = iv;
    }

    public String getMac() {
        return mac;
    }

    public void setMac(String mac) {
        this.mac = mac;
    }

    public String getCiphertext() {
        return ciphertext;
    }

    public void setCiphertext(String ciphertext) {
        this.ciphertext = ciphertext;
    }
}
