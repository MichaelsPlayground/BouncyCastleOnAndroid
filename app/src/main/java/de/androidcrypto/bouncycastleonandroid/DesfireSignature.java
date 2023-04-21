package de.androidcrypto.bouncycastleonandroid;

import org.bouncycastle.jcajce.provider.asymmetric.util.EC5Util;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.math.ec.ECCurve;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;


public class DesfireSignature {

    private static StringBuilder sb;

    public static String doDesfireSignature() {
        sb = new StringBuilder();
        printX("1 Build the EC Public Key");

        String publicKeyNxpShow = "0x040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D";
        String publicKeyNxpString = "040E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D";
        String tagSignatureString = "1CA298FC3F0F04A329254AC0DF7A3EB8E756C076CD1BAAF47B8BBA6DCD78BCC64DFD3E80E679D9A663CAE9E4D4C2C77023077CC549CE4A61";
        String tagIdString = "045A115A346180";
        byte[] publicKeyNxp = Utils.hexToBytes(publicKeyNxpString);
        byte[] tagSignatureByte = Utils.hexToBytes(tagSignatureString);
        byte[] tagIdByte = Utils.hexToBytes(tagIdString);

        ECPublicKey ecPubKey = null;
        try {
            ecPubKey = decodeKeySecp224r1(publicKeyNxp);
        } catch (InvalidKeySpecException | NoSuchAlgorithmException | NoSuchProviderException e) {
            //throw new RuntimeException(e);
            printX("Error in decoding EC Public Key: " + e.getMessage());
        }

        PublicKey pubKey = null;
        if (ecPubKey == null) {
            printX("ecPubKey is NULL");
        } else {
            printX("2 ecPubKey: " + ecPubKey.toString());
            pubKey = (PublicKey) ecPubKey;
            printX("2 pubKey: " + pubKey.toString());

            printX("3 verify the signature");
            printX("signature length: " + tagSignatureByte.length + " data: " + Utils.bytesToHex(tagSignatureByte));
            boolean sigCheck = false;
            try {
                sigCheck = checkEcdsaSignatureEcPubKey(ecPubKey, tagSignatureByte, tagIdByte);
            } catch (NoSuchAlgorithmException e) {
                //throw new RuntimeException(e);
                printX("Error in checkEcdsaSignatureEcPubKey: " + e.getMessage());
            }
            printX("4 verify the signature result: " + String.valueOf(sigCheck));
        }

        boolean sigVer = false;
        try {
            printX("Bouncy Castle PubKey with native check");
            printX("in checkEcdsaSignature publicKey: " + pubKey.toString());
            printX("Bouncy pubKey: " + Utils.bytesToHex(pubKey.getEncoded()));
            printX("Bouncy pubKey: " + pubKey.getAlgorithm());
            //printX("data = tagUid: " + Utils.bytesToHex(data));
            //printX("signature: " + Utils.bytesToHex(signature));

            final Signature dsa = Signature.getInstance("NONEwithECDSA");
            dsa.initVerify(pubKey);
            dsa.update(tagIdByte);
            //return dsa.verify(derEncodeSignature(signature)); // for secp224r1
            byte[] derEncodedSignature = derEncodeSignatureSecp224r1(tagSignatureByte);
            printX("derEncodedSignature: " + Utils.bytesToHex(derEncodedSignature));
            sigVer = dsa.verify(derEncodedSignature); // for secp224r1
        } catch (final SignatureException | InvalidKeyException |
                       NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        printX("sigCheck: " + sigVer);



        printX("");
        printX("DesFire signature verification wihout BC");
        boolean sigCheckNative = false;
        try {
            sigCheckNative = checkEcdsaSignature(publicKeyNxpString, tagSignatureByte, tagIdByte);
        } catch (NoSuchAlgorithmException e) {
            //throw new RuntimeException(e);
            printX("Error in checkEcdsaSignature: " + e.getMessage());
        }
        printX("4 verify the signature native result: " + String.valueOf(sigCheckNative));


        printX("");
        printX("Other method to get the key");
        String name = "secp224r1";
        int size = 224;
        byte[] head = new byte[0];
        try {
            head = createHeadForNamedCurve(name, size);
        } catch (NoSuchAlgorithmException | InvalidAlgorithmParameterException | IOException e) {
            //throw new RuntimeException(e);
            printX("Error: " + e.getMessage());
        }
        printX("header for method: " + Utils.base64Encoding(head));
        byte[] w = Utils.hexToBytes("0E98E117AAA36457F43173DC920A8757267F44CE4EC5ADD3C54075571AEBBF7B942A9774A1D94AD02572427E5AE0A2DD36591B1FB34FCF3D");
        ECPublicKey key = null;
        try {
            key = generateP256PublicKeyFromFlatW(w);
        } catch (InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }
        printX("pKey: " + key.toString());
        printX("pKey: " + Utils.bytesToHex(key.getEncoded()));
        printX("3 verify the signature");
        printX("signature length: " + tagSignatureByte.length + " data: " + Utils.bytesToHex(tagSignatureByte));
        boolean sigCheck = false;
        try {
            sigCheck = checkEcdsaSignatureEcPubKey(ecPubKey, tagSignatureByte, tagIdByte);
        } catch (NoSuchAlgorithmException e) {
            //throw new RuntimeException(e);
            printX("Error in checkEcdsaSignatureEcPubKey: " + e.getMessage());
        }
        printX("4 verify the signature result: " + String.valueOf(sigCheck));


        return sb.toString();
    }

    /**
     * this is the code using Bouncy Castle start
     */

    // https://stackoverflow.com/a/33347595/8166854
    public static ECPublicKey decodeKeySecp224r1(byte[] encoded) throws InvalidKeySpecException, NoSuchAlgorithmException, NoSuchProviderException {
        ECNamedCurveParameterSpec params = ECNamedCurveTable.getParameterSpec("secp224r1");
        KeyFactory fact = KeyFactory.getInstance("ECDSA", "BC");
        ECCurve curve = params.getCurve();
        java.security.spec.EllipticCurve ellipticCurve = EC5Util.convertCurve(curve, params.getSeed());
        java.security.spec.ECPoint point = ECPointUtil.decodePoint(ellipticCurve, encoded);
        java.security.spec.ECParameterSpec params2 =EC5Util.convertSpec(ellipticCurve, params);
        java.security.spec.ECPublicKeySpec keySpec = new java.security.spec.ECPublicKeySpec(point,params2);

        // print out the keySpec
        printX("params.getCurve.getA: " + keySpec.getParams().getCurve().getA());
        printX("params.getCurve.getB: " + keySpec.getParams().getCurve().getB());
        printX("params.getCurve.getCoFactor: " + keySpec.getParams().getCofactor());
        //final BigInteger p = ((ECFieldFp) params.getCurve().getField()).getP();
        //printlnX("params.getCurve.getP: " + p);
        printX("params.getCurve.getOrder: " + keySpec.getParams().getOrder());
        printX("params.getCurve.getX: " + keySpec.getW().getAffineX());
        printX("params.getCurve.getY: " + keySpec.getW().getAffineY());
        printX("params.getCurve.Field characteristic: " + curve.getField().getCharacteristic());

        return (ECPublicKey) fact.generatePublic(keySpec);
    }

    public static boolean checkEcdsaSignatureEcPubKey(final ECPublicKey
                                                      ecPubKey, final byte[]
                                                      signature, final byte[] data)
            throws NoSuchAlgorithmException
    {
            try {
                //final PublicKey publicKey = keyFac.generatePublic(ecPubKey);
                final Signature dsa = Signature.getInstance("NONEwithECDSA");
                dsa.initVerify(ecPubKey);
                dsa.update(data);
                return dsa.verify(derEncodeSignatureSecp224r1(signature));
            } catch (final SignatureException | InvalidKeyException e) {
                e.printStackTrace();
            }
        return false;
    }

    public static byte[] derEncodeSignatureSecp224r1(final byte[] signature) {
        // split into r and s
        final byte[] r = Arrays.copyOfRange(signature, 0, 28);
        final byte[] s = Arrays.copyOfRange(signature, 28, 56);
        /* code for secp128r1
        final byte[] r = Arrays.copyOfRange(signature, 0, 16);
        final byte[] s = Arrays.copyOfRange(signature, 16, 32);
        */
        int rLen = r.length;
        int sLen = s.length;
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }
        final byte[] encodedSig = new byte[rLen + sLen + 6]; // 6 T and L bytes
        encodedSig[0] = 0x30; // SEQUENCE
        encodedSig[1] = (byte) (4 + rLen + sLen);
        encodedSig[2] = 0x02; // INTEGER
        encodedSig[3] = (byte) rLen;
        encodedSig[4 + rLen] = 0x02; // INTEGER
        encodedSig[4 + rLen + 1] = (byte) sLen;

        // copy in r and s
        encodedSig[4] = 0;
        encodedSig[4 + rLen + 2] = 0;
        System.arraycopy(r, 0, encodedSig, 4 + rLen - r.length, r.length);
        System.arraycopy(s, 0, encodedSig, 4 + rLen + 2 + sLen - s.length,
                s.length);

        return encodedSig;
    }
    // END code from NXP's AN11350 document (NTAG21x Originality Signature Validation)

    /**
     * this is the code using Bouncy Castle end
     */

    /**
     * this is the code using native EC start
     */

    // START code from NXP's AN11350 document (NTAG21x Originality Signature Validation)
    public static boolean checkEcdsaSignature(final String ecPubKey,
                                              final byte[]
                                                      signature, final byte[] data) throws NoSuchAlgorithmException {
        final ECPublicKeySpec ecPubKeySpec = getEcPubKey(ecPubKey,
                getEcSecp224r1());
        if (ecPubKeySpec == null) {
            System.out.println("*** ecPubKeySpec == null");
        } else {
            System.out.println("*** ecPubKeySpec NOT null");
        }


        /*
        final ECPublicKeySpec ecPubKeySpec = getEcPubKey(ecPubKey,
                getEcSecp128r1());
        */
        return checkEcdsaSignature(ecPubKeySpec, signature, data);
    }

    public static boolean checkEcdsaSignature(final ECPublicKeySpec
                                                      ecPubKey, final byte[]
                                                      signature, final byte[] data)
            throws NoSuchAlgorithmException
    {
        KeyFactory keyFac = null;
        try {
            keyFac = KeyFactory.getInstance("ECDSA");
        } catch (final NoSuchAlgorithmException e1) {
            keyFac = KeyFactory.getInstance("EC");
        }

        if (keyFac != null) {
            try {
                final PublicKey publicKey = keyFac.generatePublic(ecPubKey);

                printX("in checkEcdsaSignature publicKey: " + publicKey.toString());
                printX("Native pubKey: " + Utils.bytesToHex(publicKey.getEncoded()));
                printX("Native pubKey: " + publicKey.getAlgorithm());
                printX("data = tagUid: " + Utils.bytesToHex(data));
                printX("signature: " + Utils.bytesToHex(signature));

                final Signature dsa = Signature.getInstance("NONEwithECDSA");
                dsa.initVerify(publicKey);
                dsa.update(data);
                //return dsa.verify(derEncodeSignature(signature)); // for secp224r1
                byte[] derEncodedSignature = derEncodeSignatureSecp224r1(signature);
                printX("derEncodedSignature: " + Utils.bytesToHex(derEncodedSignature));
                return dsa.verify(derEncodedSignature); // for secp224r1
            } catch (final SignatureException | InvalidKeySpecException | InvalidKeyException e) {
                e.printStackTrace();
            }
        }

        return false;
    }
    public static ECPublicKeySpec getEcPubKey(final String key, final
    ECParameterSpec
            curve) {
        System.out.println("*** getEcPubKey ***");
        System.out.println("key length: " + key.length());
        //if (key == null || key.length() != 2 * 33 || !key.startsWith("04")) { // curve ecp128r1
        if (key == null || key.length() != 2 * 57 || !key.startsWith("04")) { // curve Secp224r1
            System.out.println("*** getEcPubKey has to return NULL");
            return null;
        }

        final String keyX = key.substring(2, 58);
        final String keyY = key.substring(58, 114);

        printX("publicKey: " + key + " length: " + key.length());
        printX("pubKey X : " + keyX + " length: " + keyX.length());
        printX("pubKey Y : " + keyY + " length: " + keyY.length());

        final BigInteger affineX = new BigInteger(keyX, 16);
        final BigInteger affineY = new BigInteger(keyY, 16);
        final ECPoint w = new ECPoint(affineX, affineY);

        return new ECPublicKeySpec(w, curve);
    }

    public static ECParameterSpec getEcSecp224r1() {
        // see: https://github.com/Archerxy/ecdsa_java/blob/master/archer/algorithm/ecdsa/Curve.java
        // EC definition of "secp128r1":
        final BigInteger p = new
                BigInteger("26959946667150639794667015087019630673557916260026308143510066298881");
        final ECFieldFp field = new ECFieldFp(p);

        final BigInteger a = new
                BigInteger("26959946667150639794667015087019630673557916260026308143510066298878");
        final BigInteger b = new
                BigInteger("18958286285566608000408668544493926415504680968679321075787234672564");
        final EllipticCurve curve = new EllipticCurve(field, a, b);

        final BigInteger genX = new
                BigInteger("1537262966155342342542839360149858014120895768327149769731388503383");
        final BigInteger genY = new
                BigInteger("2835100677008103536657509287374498098338118978590493963520402509629");
        final ECPoint generator = new ECPoint(genX, genY);

        final BigInteger order = new
                BigInteger("26959946667150639794667015087019625940457807714424391721682722368061");
        final int cofactor = 1;

        return new ECParameterSpec(curve, generator, order, cofactor);
    }


    public static ECParameterSpec getEcSecp128r1() {
        // EC definition of "secp128r1":
        final BigInteger p = new
                BigInteger("fffffffdffffffffffffffffffffffff", 16);
        final ECFieldFp field = new ECFieldFp(p);

        final BigInteger a = new
                BigInteger("fffffffdfffffffffffffffffffffffc", 16);
        final BigInteger b = new
                BigInteger("e87579c11079f43dd824993c2cee5ed3", 16);
        final EllipticCurve curve = new EllipticCurve(field, a, b);

        final BigInteger genX = new
                BigInteger("161ff7528b899b2d0c28607ca52c5b86", 16);
        final BigInteger genY = new
                BigInteger("cf5ac8395bafeb13c02da292dded7a83", 16);
        final ECPoint generator = new ECPoint(genX, genY);

        final BigInteger order = new
                BigInteger("fffffffe0000000075a30d1b9038a115", 16);
        final int cofactor = 1;

        return new ECParameterSpec(curve, generator, order, cofactor);
    }

    public static byte[] derEncodeSignature(final byte[] signature) {
        // split into r and s
        final byte[] r = Arrays.copyOfRange(signature, 0, 16);
        final byte[] s = Arrays.copyOfRange(signature, 16, 32);

        int rLen = r.length;
        int sLen = s.length;
        if ((r[0] & 0x80) != 0) {
            rLen++;
        }
        if ((s[0] & 0x80) != 0) {
            sLen++;
        }
        final byte[] encodedSig = new byte[rLen + sLen + 6]; // 6 T and L bytes
        encodedSig[0] = 0x30; // SEQUENCE
        encodedSig[1] = (byte) (4 + rLen + sLen);
        encodedSig[2] = 0x02; // INTEGER
        encodedSig[3] = (byte) rLen;
        encodedSig[4 + rLen] = 0x02; // INTEGER
        encodedSig[4 + rLen + 1] = (byte) sLen;

        // copy in r and s
        encodedSig[4] = 0;
        encodedSig[4 + rLen + 2] = 0;
        System.arraycopy(r, 0, encodedSig, 4 + rLen - r.length, r.length);
        System.arraycopy(s, 0, encodedSig, 4 + rLen + 2 + sLen - s.length,
                s.length);

        return encodedSig;
    }
    // END code from NXP's AN11350 document (NTAG21x Originality Signature Validation)

    /**
     * this is the code using native EC start
     */

    // https://stackoverflow.com/a/30471945/8166854 answered May 27, 2015 at 2:03 by Maarten Bodewes
    //private static byte[] P256_HEAD = Utils.base64Decoding("MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE");
    //private static byte[] P256_HEAD = Utils.base64Decoding("ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE"); // this is the header of secp224r1

    // generate this value once for a curve by using createHeadForNamedCurve
    // e.g. secp224r1 length 224 or NIST P-256 length 256
    private static byte[] SECP224R1_HEAD = Utils.base64Decoding("ME4wEAYHKoZIzj0CAQYFK4EEACEDOgAE"); // this is the header of secp224r1

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     * @param w a 64 byte uncompressed EC point consisting of just a 256-bit X and Y
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public static ECPublicKey generateP256PublicKeyFromFlatW(byte[] w) throws InvalidKeySpecException {
        byte[] encodedKey = new byte[SECP224R1_HEAD.length + w.length];
        System.arraycopy(SECP224R1_HEAD, 0, encodedKey, 0, SECP224R1_HEAD.length);
        System.arraycopy(w, 0, encodedKey, SECP224R1_HEAD.length, w.length);
        KeyFactory eckf;
        try {
            eckf = KeyFactory.getInstance("EC");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("EC key factory not present in runtime");
        }
        X509EncodedKeySpec ecpks = new X509EncodedKeySpec(encodedKey);
        return (ECPublicKey) eckf.generatePublic(ecpks);
    }

    /**
     * Converts an uncompressed secp256r1 / P-256 public point to the EC public key it is representing.
     * @param w a 64 byte uncompressed EC point starting with <code>04</code>
     * @return an <code>ECPublicKey</code> that the point represents
     */
    public static ECPublicKey generateP256PublicKeyFromUncompressedW(byte[] w) throws InvalidKeySpecException {
        if (w[0] != 0x04) {
            throw new InvalidKeySpecException("w is not an uncompressed key");
        }
        return generateP256PublicKeyFromFlatW(Arrays.copyOfRange(w, 1, w.length));
    }

    private static byte[] createHeadForNamedCurve(String name, int size)
            throws NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, IOException {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec m = new ECGenParameterSpec(name);
        kpg.initialize(m);
        KeyPair kp = kpg.generateKeyPair();
        byte[] encoded = kp.getPublic().getEncoded();
        return Arrays.copyOf(encoded, encoded.length - 2 * (size / Byte.SIZE));
    }





    private static void printX(String message) {
        System.out.println(message);
        sb.append(message).append("\n");
    }

}
