
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Base64;

public class SSL {

    private static int bitEncryption = 2048;
    private static SecureRandom random = new SecureRandom();
    private static String initVector = "encryptionIntVec";
    private static BigInteger salt = new BigInteger("1234789012347890");

    public static BigInteger primeGen() {

        return BigInteger.probablePrime(bitEncryption / 2, random);

    }

    public static BigInteger modulusGen(BigInteger p, BigInteger q) {

        return p.multiply(q);

    }

    public static BigInteger RSAencrypt(String message, BigInteger e, BigInteger n) {

        return toBigInt(message).modPow(e, n);
    }

    public static BigInteger toBigInt(String input) {

        return new BigInteger(input.getBytes());

    }

    public static BigInteger DHrandom(BigInteger DHp) {
        BigInteger DHa;
        do {
            DHa = new BigInteger(DHp.bitLength(), random);

        } while (DHa.compareTo(DHp) >= 0);
        return DHa;
    }

    public static BigInteger DHpubKeyGen(BigInteger dHa, BigInteger dHg, BigInteger dHp) {
        return dHg.modPow(dHa, dHp);
    }

    public static BigInteger findN(String message) {
        Pattern p2 = Pattern.compile("(n=\\d+)");
        Matcher m2 = p2.matcher(message);
        m2.find();
        BigInteger n = new BigInteger(m2.group(0).substring(2));
        return n;

    }

    public static BigInteger findE(String message) {
        Pattern p = Pattern.compile("(e=\\d+)");
        Matcher m = p.matcher(message);
        m.find();
        BigInteger e = new BigInteger(m.group(0).substring(2));
        return e;

    }

    public static BigInteger findDHg(String message) {
        Pattern p = Pattern.compile("(DHg=\\d+)");
        Matcher m = p.matcher(message);
        m.find();
        BigInteger e = new BigInteger(m.group(0).substring(4));
        return e;

    }

    public static BigInteger findDHp(String message) {
        Pattern p = Pattern.compile("(DHp=\\d+)");
        Matcher m = p.matcher(message);
        m.find();
        BigInteger e = new BigInteger(m.group(0).substring(4));
        return e;

    }

    public static BigInteger findDHpubkey(String message) {
        Pattern p = Pattern.compile("(DHpubkey=\\d+)");
        Matcher m = p.matcher(message);
        m.find();
        BigInteger e = new BigInteger(m.group(0).substring(9));
        return e;

    }

    public static BigInteger calculateSessionKey(BigInteger dHserverKey, BigInteger dHb, BigInteger dHp) {
        return dHserverKey.modPow(dHb, dHp);
    }

    public static String AESencrypt(BigInteger sessionKey, String message) {
        try {
            String key = sessionKey.toString();
            SecretKeySpec skeySpec = setKey(key);
            IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);

            return initVector + " " + Base64.getEncoder().encodeToString(cipher.doFinal(message.getBytes("UTF-8")));
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return null;
    }

    public static String AESdecrypt(String encrypted, BigInteger sessionKey) {
        try {
            String key = sessionKey.toString();
            SecretKeySpec skeySpec = setKey(key);

            String ivm = encrypted.split(" ")[0];
            String messageEncypted = encrypted.split(" ")[1];

            IvParameterSpec iv = new IvParameterSpec(ivm.getBytes("UTF-8"));

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
            return new String(cipher.doFinal(Base64.getDecoder().decode(messageEncypted)));
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        return null;
    }

    public static SecretKeySpec setKey(String myKey) throws NoSuchAlgorithmException, UnsupportedEncodingException {
        MessageDigest sha = null;
        byte[] key;
        SecretKeySpec secretKey;
        key = myKey.getBytes("UTF-8");
        sha = MessageDigest.getInstance("SHA-256");
        key = sha.digest(key);
        key = Arrays.copyOf(key, 16);
        secretKey = new SecretKeySpec(key, "AES");
        return secretKey;
    }

}
