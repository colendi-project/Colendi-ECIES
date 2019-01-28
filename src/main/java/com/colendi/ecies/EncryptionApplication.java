package com.colendi.ecies;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.bouncycastle.asn1.sec.SECNamedCurves;
import org.bouncycastle.asn1.x9.X9ECParameters;
import org.bouncycastle.asn1.x9.X9IntegerConverter;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.agreement.ECDHBasicAgreement;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.generators.ECKeyPairGenerator;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve;
import org.bouncycastle.util.BigIntegers;
import org.bouncycastle.util.encoders.Hex;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;


@SpringBootApplication
@RestController
public class EncryptionApplication {

	public static void main(String[] args) {
		SpringApplication.run(EncryptionApplication.class, args);
	}

	private static final String ALGORITHM = "ECDSA";
	private static final String CURVE_NAME = "secp256k1";
	private static final String PROVIDER = "BC";

	static ECDomainParameters CURVE;
	static BigInteger CURVE_ORDER;
	static BigInteger HALF_CURVE_ORDER;
	static KeyPairGenerator KEY_PAIR_GENERATOR;
	static X9IntegerConverter X_9_INTEGER_CONVERTER;
	static ECGenParameterSpec ecGenParameterSpec;
	static X9ECParameters x9ECParameters;

	@RequestMapping(value = "/", method = RequestMethod.GET)
	public EncryptedResult getEncryptedResult(@RequestParam("word") String plainText, @RequestParam("pubKey") String pubKey) {
		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator keyPairGenerator = getKPGenerator();
		//KeyPair keyPair = keyPairGenerator.generateKeyPair();

		//BCECPrivateKey priv = (BCECPrivateKey)keyPair.getPrivate();
		//BCECPublicKey pub = (BCECPublicKey)keyPair.getPublic();


		//String privHex = priv.getD().toString(16);

		ECPoint ecPoint = CURVE.getCurve().decodePoint(BigIntegers.asUnsignedByteArray(new BigInteger(pubKey, 16)));

		try {
			EncryptedResult result = this.encrypt(ecPoint,plainText);
			//result.setPrivateKey(privHex);
			return result;
		} catch (Exception e) {
			System.out.println(plainText);
			return new EncryptedResult("", "", "", "", "");
		}
	}

	public static KeyPairGenerator getKPGenerator(){
		try {
			Class.forName("org.bouncycastle.asn1.sec.SECNamedCurves");
		} catch (ClassNotFoundException e) {
			throw new IllegalStateException(
					"BouncyCastle is not available on the classpath, see https://www.bouncycastle.org/latest_releases.html");
		}
		x9ECParameters = SECNamedCurves.getByName(CURVE_NAME);
		CURVE = new ECDomainParameters(x9ECParameters.getCurve(), x9ECParameters.getG(), x9ECParameters.getN(), x9ECParameters.getH());
		CURVE_ORDER = CURVE.getN();
		HALF_CURVE_ORDER = CURVE_ORDER.shiftRight(1);
		if (CURVE_ORDER.compareTo(SecP256K1Curve.q) >= 0) {
			throw new IllegalStateException("secp256k1.n should be smaller than secp256k1.q, but is not");
		}
		try {
			KEY_PAIR_GENERATOR = KeyPairGenerator.getInstance(ALGORITHM, PROVIDER);
		} catch (NoSuchProviderException e) {
			throw new IllegalStateException(
					"BouncyCastleProvider is not available, see https://www.bouncycastle.org/wiki/display/JA1/Provider+Installation",
					e);
		} catch (NoSuchAlgorithmException e) {
			throw new IllegalStateException("Algorithm should be available but was not", e);
		}
		ecGenParameterSpec = new ECGenParameterSpec(CURVE_NAME);
		try {
			KEY_PAIR_GENERATOR.initialize(ecGenParameterSpec, new SecureRandom());
		} catch (InvalidAlgorithmParameterException e) {
			throw new IllegalStateException("Algorithm parameter should be available but was not", e);
		}

		X_9_INTEGER_CONVERTER = new X9IntegerConverter();

		return KEY_PAIR_GENERATOR;

	}

	public EncryptedResult encrypt(ECPoint toPub, String plainText) throws Exception {
		ECKeyPairGenerator eGen = new ECKeyPairGenerator();
		SecureRandom random = new SecureRandom();
		KeyGenerationParameters gParam = new ECKeyGenerationParameters(CURVE, random);

		eGen.init(gParam);

		AsymmetricCipherKeyPair ephemPair = eGen.generateKeyPair();
		BigInteger ephemPrivatep = ((ECPrivateKeyParameters)ephemPair.getPrivate()).getD();
		ECPoint ephemPub = ((ECPublicKeyParameters)ephemPair.getPublic()).getQ();

		MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");

		BigInteger derivedKey = calculateKeyAgreement(ephemPrivatep, toPub);

		byte[] derivedKeyInBytes = BigIntegers.asUnsignedByteArray(derivedKey);
		byte[] digestKey = new byte[32];
		System.arraycopy(derivedKeyInBytes,0,digestKey,32-derivedKeyInBytes.length, derivedKeyInBytes.length);

		byte [] digested = mda.digest(digestKey);

		String strDigested = new String(Hex.encode(digested));

		String encKeyAES = strDigested.substring(0,64);
		String macKey = strDigested.substring(64);

		byte[] IV = new byte[16];
		new SecureRandom().nextBytes(IV);

		byte[] encryptedMsg = encryptAES256CBC(plainText, encKeyAES, IV);

		byte[] ephemPubBytes = ephemPub.getEncoded(false);

		byte[] dataToMac = generateMAC(IV,ephemPubBytes,encryptedMsg);

		byte[] HMac = getHMAC(Hex.decode(macKey),dataToMac);

		System.out.println("-----START-----");
		System.out.println("word : " +  plainText);
		System.out.println("Ephem private : " +  ephemPrivatep.toString(16));
		System.out.println("Ephem public : " + "0x" + ephemPub.getXCoord()+ephemPub.getYCoord());
		System.out.println("derivedKey : " +  derivedKey.toString(16));
		System.out.println("sha-512 of derivedKey : " + strDigested);
		System.out.println("aes enc key :" + encKeyAES);
		System.out.println("mac key :" +  macKey);
		System.out.println("iv:" + new String(Hex.encode(IV)));
		System.out.println("dataTomac : " + new String(Hex.encode(dataToMac)));
        System.out.println("hmac : " + new String(Hex.encode(HMac)));
		System.out.println("-----END-----");

		String ephemPubString = new String(Hex.encode(ephemPubBytes));
		String ivString = new String(Hex.encode(IV));
		String macString = new String(Hex.encode((HMac)));
		String encryptedText = new String(Hex.encode(encryptedMsg));


		return new EncryptedResult("PrivateKey", ephemPubString, ivString, macString, encryptedText);
	}

	public static BigInteger calculateKeyAgreement(BigInteger privKey, ECPoint theirPubKey) {

		ECPrivateKeyParameters privKeyP =
				new ECPrivateKeyParameters(privKey, CURVE);
		ECPublicKeyParameters pubKeyP = new ECPublicKeyParameters(theirPubKey, CURVE);

		ECDHBasicAgreement agreement = new ECDHBasicAgreement();
		agreement.init(privKeyP);
		return agreement.calculateAgreement(pubKeyP);
	}

	private static byte [] encryptAES256CBC(String plaintext, String encKey,  byte[] IV) throws Exception {

		SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decode(encKey), "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
		return cipher.doFinal(plaintext.getBytes());
	}


	private static byte[] generateMAC(byte[] IV , byte[] ephemPublicKey, byte[] ciphertext) throws IOException {
		ByteArrayOutputStream bos = new ByteArrayOutputStream();

		bos.write(IV);
		bos.write(ephemPublicKey);
		bos.write(ciphertext);

		byte[] dataToMac = bos.toByteArray();

		return dataToMac;

	}

	private static byte[] getHMAC(byte[] macKey, byte[] dataToMac ){

		HMac hmac = new HMac(new SHA256Digest());
		byte[] resBuf=new byte[hmac.getMacSize()];
		hmac.init(new KeyParameter(macKey));
		hmac.update(dataToMac,0,dataToMac.length);
		hmac.doFinal(resBuf,0);

		return resBuf;

	}

	public static String decrypt(BigInteger privKey, String IV, String ephemPublicKey, String ciphertext, String mac) throws Exception {

		ECPoint ecPoint = CURVE.getCurve().decodePoint(BigIntegers.asUnsignedByteArray(new BigInteger(ephemPublicKey, 16)));

		MessageDigest mda = MessageDigest.getInstance("SHA-512", "BC");

		BigInteger derivedKey = calculateKeyAgreement(privKey, ecPoint);


		byte[] derivedKeyInBytes = BigIntegers.asUnsignedByteArray(derivedKey);
		byte[] digestKey = new byte[32];
		System.arraycopy(derivedKeyInBytes,0,digestKey,32-derivedKeyInBytes.length, derivedKeyInBytes.length);

		byte [] digested = mda.digest(digestKey);

		String strDigested = new String(Hex.encode(digested));

		String encKeyAES = strDigested.substring(0,64);
		String macKey = strDigested.substring(64);


		byte[] ephemPubBytes = ecPoint.getEncoded(false);

		byte[] dataToMac = generateMAC(Hex.decode(IV),ephemPubBytes,Hex.decode(ciphertext));

		byte[] HMac = getHMAC(Hex.decode(macKey),dataToMac);

		if(MessageDigest.isEqual(HMac, Hex.decode(mac))){
			String decryptedMsg = decryptAES256CBC(Hex.decode(ciphertext), encKeyAES,Hex.decode(IV));
			return decryptedMsg;
		}
		else {
			return "BAD-MAC";
		}
	}



	private static String decryptAES256CBC(byte [] ciphertext, String encKey,  byte[] IV) throws Exception {
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7Padding");
		SecretKeySpec secretKeySpec = new SecretKeySpec(Hex.decode(encKey), "AES");
		cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, new IvParameterSpec(IV));
		return new String(cipher.doFinal(ciphertext));
	}


}

