package fhw;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.bcpg.BCPGKey;
import org.bouncycastle.bcpg.PublicKeyPacket;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.PGPCompressedData;
import org.bouncycastle.openpgp.PGPEncryptedDataList;
import org.bouncycastle.openpgp.PGPSecretKey;
import org.bouncycastle.openpgp.PGPException;
import org.bouncycastle.openpgp.PGPLiteralData;
import org.bouncycastle.openpgp.PGPObjectFactory;
import org.bouncycastle.openpgp.PGPOnePassSignatureList;
import org.bouncycastle.openpgp.PGPPrivateKey;
import org.bouncycastle.openpgp.PGPPublicKeyEncryptedData;
import org.bouncycastle.openpgp.PGPSecretKeyRing;
import org.bouncycastle.openpgp.PGPUtil;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.jcajce.JcePBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.PGPSecretKeyRingCollection;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.KeyFingerPrintCalculator;
import org.bouncycastle.openpgp.operator.PBESecretKeyDecryptor;
import org.bouncycastle.openpgp.operator.bc.BcKeyFingerprintCalculator;
import org.bouncycastle.openpgp.operator.bc.BcPBESecretKeyDecryptorBuilder;
import org.bouncycastle.openpgp.operator.bc.BcPGPDigestCalculatorProvider;
import org.bouncycastle.openpgp.operator.bc.BcPublicKeyDataDecryptorFactory;
import org.bouncycastle.openpgp.operator.jcajce.JcaPGPDigestCalculatorProviderBuilder;

public class Dec1
{
            
    public static void main1(String args[]) 
            throws FileNotFoundException, IOException, PGPException
    {
        System.out.println("main!");        
        Security.addProvider(new BouncyCastleProvider());        
        FileInputStream in = new FileInputStream("/home/fwelland/ls-secret-key.pgp");
        Dec1 d = new Dec1();
        String passphrase = "skywalker"; 
        d.loadPrivateKeyFromStream(in, passphrase);
                
    }
    
    public static void main2(String args[]) 
            throws FileNotFoundException, IOException, PGPException
    {
        System.out.println("main!");        
        Security.addProvider(new BouncyCastleProvider());        
        FileInputStream in = new FileInputStream("/home/fwelland/ls-secret-key.pgp");
        Dec1 d = new Dec1();
        String passphrase = "skywalker"; 
        long keyid = 2800194264726158558L;
        PGPPrivateKey k1 = d.findSecretKey(in, keyid, passphrase.toCharArray());                
        if(null != k1)
        {
            System.out.println("k1 hex key id:  " + d.get8DigitKeyId(k1.getKeyID()));
            System.out.println(k1.getPrivateKeyDataPacket().getEncoded());
        }
        in.close();
        in = new FileInputStream("/home/fwelland/ls-secret-key.pgp");
        
        keyid = 526892173014186197l;
        PGPPrivateKey k2 = d.findSecretKey(in, keyid, passphrase.toCharArray());                
        if(null != k2)
        {
            System.out.println("k2 hex key id:  " + d.get8DigitKeyId(k2.getKeyID()));
            System.out.println(k2.getPrivateKeyDataPacket().getEncoded());
        }        
        else
        {
            System.out.println("no private key found!!!");
        }
    }    
                
    public String get8DigitKeyId(long kid)
    {
        String s = Long.toHexString(kid); 
        s = s.substring(s.length() -8);
        return(s.toUpperCase());
    }
    
    public void loadPrivateKeyFromStream(InputStream in, String passphrase) 
        throws IOException, PGPException
    {      
        InputStream is = PGPUtil.getDecoderStream(in);
        System.out.println("what is the stram type:  " + is.toString());
        
        PGPPrivateKey privKey = null;
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(is, new JcaKeyFingerprintCalculator());
        Iterator ringIter = pgpSec.getKeyRings();
        while(ringIter.hasNext())
        {
            PGPSecretKeyRing ring= (PGPSecretKeyRing)ringIter.next();
            Iterator keyIter = ring.getSecretKeys();
            System.out.println("*****");
            while(keyIter.hasNext())
            {
                System.out.println("-----------");
                PGPSecretKey key = (PGPSecretKey)keyIter.next();
                long kid = key.getKeyID(); 
                System.out.println("keyid as a long:  " + kid);                
                System.out.println("key id as hex string:  " + Long.toHexString(kid));
                System.out.println("key id as 8digit hex string:  " + get8DigitKeyId(kid));                
                System.out.println("is signing key: " + key.isSigningKey());
                System.out.println("is the key empty?  " + key.isPrivateKeyEmpty());
                //key.
                PGPPrivateKey pk = extractPrivateKey(key, passphrase);
                if(null != pk)
                {
                    System.out.println("oh wow..now what");
                    long pkid = pk.getKeyID();
                    System.out.println("private key id:  " + get8DigitKeyId(pkid));
                    BCPGKey pgkey = pk.getPrivateKeyDataPacket();
                    System.out.println(pgkey.getFormat());
                    byte data[] = pgkey.getEncoded();
                    System.out.println(data.toString());
                }
            }
        }
    }
    
    private PGPPrivateKey extractPrivateKey(PGPSecretKey secretKey, String passPhrase)
        throws PGPException
    {
        char[] pass = passPhrase.toCharArray();
        PBESecretKeyDecryptor secretKeyDecryptor = new JcePBESecretKeyDecryptorBuilder()
            .setProvider(BouncyCastleProvider.PROVIDER_NAME).build(pass);
        PGPPrivateKey pkey = secretKey.extractPrivateKey(secretKeyDecryptor);
        return(pkey);
    }
        
    public PGPSecretKey loadPrivateKeyFromStream2(InputStream in, long keyId)
        throws IOException, PGPException
    {
        in = PGPUtil.getDecoderStream(in);
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(in, new BcKeyFingerprintCalculator());
        PGPSecretKey key = pgpSec.getSecretKey(keyId);
        if (key == null)
        {
            throw new IllegalArgumentException("Can't find encryption key in key ring.");
        }
        return key;
    }
    
    public PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
            throws IOException, PGPException
    {
        KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
        PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), calculator);
        PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
        if (pgpSecKey == null)
        {
            return null;
        }
        PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
        return pgpSecKey.extractPrivateKey(decryptor);
    }
    
    
    
    public static void main(String args[]) 
            throws FileNotFoundException, IOException, PGPException
    {
        System.out.println("main!");        
        Security.addProvider(new BouncyCastleProvider());        
        FileInputStream secretKeyIn = new FileInputStream("/home/fwelland/ls-secret-key.pgp");
        Dec1 d = new Dec1();
        String passphrase = "skywalker"; 
        FileOutputStream clearOut = new FileOutputStream("/home/fwelland/someoutput.dat"); 
        FileInputStream cypherIn = new FileInputStream("/home/fwelland/dv-message.txt.gpg");         
        d.decrypt(cypherIn, clearOut, secretKeyIn, passphrase);
                
    }    
    
    public void decrypt(InputStream cypherText,
                        OutputStream clearText, 
                        InputStream privateKeyInputStream,
                        String privateKeyPassPhrase)
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            InputStream in = PGPUtil.getDecoderStream(cypherText);            
            PGPObjectFactory pgpObjFactory = new JcaPGPObjectFactory(in); 
            PGPEncryptedDataList enc;
            Object o = pgpObjFactory.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof  PGPEncryptedDataList) 
            {
                enc = (PGPEncryptedDataList) o;
            }
            else
            {
                enc = (PGPEncryptedDataList) pgpObjFactory.nextObject();
            }            
            //
            // find the secret key
            //
            Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
            PGPPublicKeyEncryptedData pbe = null;
            PGPPrivateKey sKey = null;
            while (sKey == null && it.hasNext())
            {
                pbe = it.next();
                sKey = findSecretKey(privateKeyInputStream, pbe.getKeyID(), privateKeyPassPhrase.toCharArray());
            }
            if (sKey == null) 
            {
                throw new IllegalArgumentException("Secret key for message not found.");
            }                                               
            InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
            PGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof  PGPCompressedData)
            {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }            
            
            if (message instanceof  PGPLiteralData) 
            {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0) 
                {
                    clearText.write(ch);
                }
            }
            else if (message instanceof  PGPOnePassSignatureList)
            {
                throw new PGPException("Encrypted message contains a signed message - not literal data.");
            } 
            else
            {
                throw new PGPException("Message is not a simple encrypted file - type unknown.");
            }
            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify()) 
                {
                    throw new PGPException("Message failed integrity check");
                }
            }                     
        }
        catch(Exception e)
        {
            e.printStackTrace();
        }
    }
}

//    @SuppressWarnings("unchecked")
//    public static void decryptFile(InputStream in, OutputStream out, InputStream keyIn, char[] passwd)
//        throws Exception
//    {
//        Security.addProvider(new BouncyCastleProvider());
// 
//        in = org.bouncycastle.openpgp.PGPUtil.getDecoderStream(in);
// 
//        PGPObjectFactory pgpF = new PGPObjectFactory(in);
//        PGPEncryptedDataList enc;
// 
//        Object o = pgpF.nextObject();
//        //
//        // the first object might be a PGP marker packet.
//        //
//        if (o instanceof  PGPEncryptedDataList) {
//            enc = (PGPEncryptedDataList) o;
//        } else {
//            enc = (PGPEncryptedDataList) pgpF.nextObject();
//        }
// 
//        //
//        // find the secret key
//        //
//        Iterator<PGPPublicKeyEncryptedData> it = enc.getEncryptedDataObjects();
//        PGPPrivateKey sKey = null;
//        PGPPublicKeyEncryptedData pbe = null;
// 
//        while (sKey == null && it.hasNext()) {
//            pbe = it.next();
// 
//            sKey = findPrivateKey(keyIn, pbe.getKeyID(), passwd);
//        }
// 
//        if (sKey == null) {
//            throw new IllegalArgumentException("Secret key for message not found.");
//        }
// 
//        InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
// 
//        PGPObjectFactory plainFact = new PGPObjectFactory(clear);
// 
//        Object message = plainFact.nextObject();
// 
//        if (message instanceof  PGPCompressedData) {
//            PGPCompressedData cData = (PGPCompressedData) message;
//            PGPObjectFactory pgpFact = new PGPObjectFactory(cData.getDataStream());
// 
//            message = pgpFact.nextObject();
//        }
// 
//        if (message instanceof  PGPLiteralData) {
//            PGPLiteralData ld = (PGPLiteralData) message;
// 
//            InputStream unc = ld.getInputStream();
//            int ch;
// 
//            while ((ch = unc.read()) >= 0) {
//                out.write(ch);
//            }
//        } else if (message instanceof  PGPOnePassSignatureList) {
//            throw new PGPException("Encrypted message contains a signed message - not literal data.");
//        } else {
//            throw new PGPException("Message is not a simple encrypted file - type unknown.");
//        }
// 
//        if (pbe.isIntegrityProtected()) {
//            if (!pbe.verify()) {
//                throw new PGPException("Message failed integrity check");
//            }
//        }
//    }


//public void signData(final String privKeyData, final String password, final String data, Promise promise) {
//    try {
//      // region Decode Private Key
//      PGPSecretKey secKey = PGPUtils.getSecretKey(privKeyData);
//      PGPPrivateKey privKey = PGPUtils.decryptArmoredPrivateKey(secKey, password);
//      // endregion
//      // region Sign Data
//      String signature = PGPUtils.signArmoredAscii(privKey, data, signatureAlgo);
//      WritableMap resultMap = Arguments.createMap();
//      resultMap.putString("asciiArmoredSignature", signature);
//      resultMap.putString("hashingAlgo",  PGPUtils.hashAlgoToString(signatureAlgo));
//      resultMap.putString("fingerPrint", Utils.bytesToHex(secKey.getPublicKey().getFingerprint()));
//      promise.resolve(resultMap);
//      // endregion
//    } catch (Exception e) {
//      promise.reject(e);
//    }
//  }


//
//
//public static void decryptFile(InputStream in, InputStream keyIn, char[] passwd, OutputStream fOut, InputStream publicKeyIn) throws IOException, NoSuchProviderException, SignatureException,
//        PGPException {
//    in = PGPUtil.getDecoderStream(in);
//
//    PGPObjectFactory pgpF = new PGPObjectFactory(in);
//    PGPEncryptedDataList enc;
//
//    Object o = pgpF.nextObject();
//    //
//    // the first object might be a PGP marker packet.
//    //
//    if (o instanceof PGPEncryptedDataList) {
//        enc = (PGPEncryptedDataList) o;
//    } else {
//        enc = (PGPEncryptedDataList) pgpF.nextObject();
//    }
//
//    //
//    // find the secret key
//    //
//    Iterator<?> it = enc.getEncryptedDataObjects();
//    PGPPrivateKey sKey = null;
//    PGPPublicKeyEncryptedData pbe = null;
//    PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn));
//
//    while (sKey == null && it.hasNext()) {
//        pbe = (PGPPublicKeyEncryptedData) it.next();
//        sKey = PGPTools.findSecretKey(pgpSec, pbe.getKeyID(), passwd);
//    }
//
//    if (sKey == null) {
//        throw new IllegalArgumentException("secret key for message not found.");
//    }
//
//    InputStream clear = pbe.getDataStream(
//            new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey));
//
//    PGPObjectFactory plainFact = new PGPObjectFactory(clear);
//
//    Object message = null;
//
//    PGPOnePassSignatureList onePassSignatureList = null;
//    PGPSignatureList signatureList = null;
//    PGPCompressedData compressedData = null;
//
//    message = plainFact.nextObject();
//    ByteArrayOutputStream actualOutput = new ByteArrayOutputStream();
//
//    while (message != null) {
//        log.trace(message.toString());
//        if (message instanceof PGPCompressedData) {
//            compressedData = (PGPCompressedData) message;
//            plainFact = new PGPObjectFactory(compressedData.getDataStream());
//            message = plainFact.nextObject();
//        }
//
//        if (message instanceof PGPLiteralData) {
//            // have to read it and keep it somewhere.
//            Streams.pipeAll(((PGPLiteralData) message).getInputStream(), actualOutput);
//        } else if (message instanceof PGPOnePassSignatureList) {
//            onePassSignatureList = (PGPOnePassSignatureList) message;
//        } else if (message instanceof PGPSignatureList) {
//            signatureList = (PGPSignatureList) message;
//        } else {
//            throw new PGPException("message unknown message type.");
//        }
//        message = plainFact.nextObject();
//    }
//    actualOutput.close();
//    PGPPublicKey publicKey = null;
//    byte[] output = actualOutput.toByteArray();
//    if (onePassSignatureList == null || signatureList == null) {
//        throw new PGPException("Poor PGP. Signatures not found.");
//    } else {
//
//        for (int i = 0; i < onePassSignatureList.size(); i++) {
//            PGPOnePassSignature ops = onePassSignatureList.get(0);
//            log.trace("verifier : " + ops.getKeyID());
//            PGPPublicKeyRingCollection pgpRing = new PGPPublicKeyRingCollection(
//                    PGPUtil.getDecoderStream(publicKeyIn));
//            publicKey = pgpRing.getPublicKey(ops.getKeyID());
//            if (publicKey != null) {
//                ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider("BC"), publicKey);
//                ops.update(output);
//                PGPSignature signature = signatureList.get(i);
//                if (ops.verify(signature)) {
//                    Iterator<?> userIds = publicKey.getUserIDs();
//                    while (userIds.hasNext()) {
//                        String userId = (String) userIds.next();
//                        log.trace("Signed by {}", userId);
//                    }
//                    log.trace("Signature verified");
//                } else {
//                    throw new SignatureException("Signature verification failed");
//                }
//            }
//        }
//
//    }
//
//    if (pbe.isIntegrityProtected() && !pbe.verify()) {
//        throw new PGPException("Data is integrity protected but integrity is lost.");
//    } else if (publicKey == null) {
//        throw new SignatureException("Signature not found");
//    } else {
//        fOut.write(output);
//        fOut.flush();
//        fOut.close();
//    }
//}


//@SuppressWarnings("rawtypes")
//public static PGPPublicKey readPublicKeyFromCol(InputStream in) throws IOException, PGPException {
//    in = PGPUtil.getDecoderStream(in);
//    PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(in, new BcKeyFingerprintCalculator());
//    PGPPublicKey key = null;
//    Iterator rIt = pgpPub.getKeyRings();
//    while (key == null && rIt.hasNext()) {
//        PGPPublicKeyRing kRing = (PGPPublicKeyRing) rIt.next();
//        Iterator kIt = kRing.getPublicKeys();
//        while (key == null && kIt.hasNext()) {
//            PGPPublicKey k = (PGPPublicKey) kIt.next();
//            if (k.isEncryptionKey()) {
//                key = k;
//            }
//        }
//    }
//    if (key == null) {
//        throw new IllegalArgumentException("Can't find encryption key in key ring.");
//    }
//    return key;
//}
    
