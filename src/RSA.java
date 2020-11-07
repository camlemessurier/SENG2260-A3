import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class RSA {

    private BigInteger privateKey;
    private BigInteger publicKey;
    private BigInteger modulus;
    SecureRandom random = new SecureRandom();
    final BigInteger one = new BigInteger("1");

    private BigInteger otherPublicKey;
    private BigInteger otherModulus;

    public RSA() {
        int bitEncryption = 2048;
        BigInteger p = BigInteger.probablePrime(bitEncryption / 2, random);
        BigInteger q = BigInteger.probablePrime(bitEncryption / 2, random);
        BigInteger totient = (p.subtract(one)).multiply(q.subtract(one));

        modulus = p.multiply(q);
        publicKey = new BigInteger("65537");
        privateKey = publicKey.modInverse(totient);
    }

    public BigInteger encrypt(String message) {

        return stringtoBigInt(message).modPow(publicKey, modulus);
    }

    public String decrypt(String message) {
        BigInteger m = new BigInteger(message);

        return new String(m.modPow(privateKey, modulus).toByteArray());
    }

    public BigInteger getPublicKey() {
        return publicKey;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public void handleSetupMessage(String message) {
        otherPublicKey = findE(message);
        otherModulus = findN(message);
    }

    public BigInteger encryptUsingOther(String message) {
        return stringtoBigInt(message).modPow(otherPublicKey, otherModulus);
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

    public static BigInteger findSig(String message) {
        Pattern p = Pattern.compile("(Sig=\\d+)");
        Matcher m = p.matcher(message);
        m.find();
        BigInteger e = new BigInteger(m.group(0));
        return e;

    }

    public static BigInteger stringtoBigInt(String input) {

        return new BigInteger(input.getBytes());

    }

    public BigInteger signatureGen(String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes());
        BigInteger hashBi = new BigInteger(hash);

        return hashBi.modPow(publicKey, modulus);
    }

    public boolean checkSig(String signature, String message) throws NoSuchAlgorithmException {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] hash = md.digest(message.getBytes());
        BigInteger hashBi = new BigInteger(hash);

        BigInteger signatureBI = stringtoBigInt(signature);
        BigInteger sigver = signatureBI.modPow(publicKey, otherModulus); /// TODO other modulus

        if (sigver == hashBi) {
            return true;
        } else {
            return false;
        }
    }

    public void setOtherModulus(String otherModulus2) {
        otherModulus = stringtoBigInt(otherModulus2);
    }

}
