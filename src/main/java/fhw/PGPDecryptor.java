package fhw;

import java.io.*;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.*;
import org.bouncycastle.util.io.Streams;

public class PGPDecryptor
{

    private InputStream cypherInput;
    private OutputStream clearOutput;
    private InputStream privateKeyInput;
    private InputStream signatureKeyStream;
    private String privateKeyPassPhrase;

    public PGPDecryptor()
    {

    }

    public void decrypt()
        throws PGPOperationException, IOException
    {
        try
        {
            Security.addProvider(new BouncyCastleProvider());
            InputStream in = PGPUtil.getDecoderStream(cypherInput);
            PGPObjectFactory pgpObjFactory = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpObjFactory.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
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
                sKey = findSecretKey(privateKeyInput, pbe.getKeyID(), privateKeyPassPhrase.toCharArray());
            }
            if (sKey == null)
            {
                throw new IllegalArgumentException("Secret key for message not found.");
            }
            InputStream clear = pbe.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
            PGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();
            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();
            }

            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                int ch;
                while ((ch = unc.read()) >= 0)
                {
                    getClearOutput().write(ch);
                }
            }
            else if (message instanceof PGPOnePassSignatureList)
            {
                throw new PGPOperationException("Encrypted message contains a signed message - not literal data.");
            }
            else
            {
                throw new PGPOperationException("Message is not a simple encrypted file - type unknown.");
            }
            if (pbe.isIntegrityProtected())
            {
                if (!pbe.verify())
                {
                    throw new PGPOperationException("Message failed integrity check");
                }
            }
        }
        catch(IOException | PGPOperationException e)
        {
            throw e; 
        }
        catch(PGPException pgpe)
        {
            throw new PGPOperationException(pgpe.getMessage(),pgpe); 
        }
    }




    protected PGPPublicKey readSignatureKey()
       throws IOException, PGPException
    {
        PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
           PGPUtil.getDecoderStream(signatureKeyStream),
           new JcaKeyFingerprintCalculator());
        Iterator keyRingIter = pgpPub.getKeyRings();
        while (keyRingIter.hasNext())
        {
            PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
            Iterator keyIter = keyRing.getPublicKeys();
            while (keyIter.hasNext())
            {
                PGPPublicKey key = (PGPPublicKey)keyIter.next();
                if (key.isEncryptionKey())
                {
                    return key;
                }
            }
        }
        throw new IllegalArgumentException("Can't find encryption key in key ring.");
    }

    public void verifySignedEncryptedObject() throws PGPOperationException, IOException
    {

        try
        {
          //  Security.addProvider(new BouncyCastleProvider());
            InputStream in = PGPUtil.getDecoderStream(cypherInput);

            PGPObjectFactory pgpObjFactory = new JcaPGPObjectFactory(in);
            PGPEncryptedDataList enc;
            Object o = pgpObjFactory.nextObject();
            //
            // the first object might be a PGP marker packet.
            //
            if (o instanceof PGPEncryptedDataList)
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
            PGPPublicKeyEncryptedData encData = (PGPPublicKeyEncryptedData)enc.get(0);

            System.out.println("VVVID="+ encData.getKeyID());

            PGPPrivateKey sKey = findSecretKey(privateKeyInput, encData.getKeyID(), privateKeyPassPhrase.toCharArray());

            System.out.println("SKEY="+ sKey);

//            PublicKeyDataDecryptorFactory dataDecryptorFactory = new JcePublicKeyDataDecryptorFactoryBuilder().setProvider("BC").build(sKey);

            InputStream clear = encData.getDataStream(new BcPublicKeyDataDecryptorFactory(sKey));
            System.out.println("CL="+ clear);

            PGPObjectFactory plainFact = new JcaPGPObjectFactory(clear);
            Object message = plainFact.nextObject();


            System.out.println("DF="+ message.getClass());

            if (message instanceof PGPCompressedData)
            {
                PGPCompressedData cData = (PGPCompressedData) message;
                PGPObjectFactory pgpFact = new JcaPGPObjectFactory(cData.getDataStream());
                message = pgpFact.nextObject();

                System.out.println("DF=2222"+ message.getClass());


            }

            if (message instanceof PGPLiteralData)
            {
                PGPLiteralData ld = (PGPLiteralData) message;
                InputStream unc = ld.getInputStream();
                byte[] signedData = Streams.readAll(unc);

                if (encData.verify())
                {
                    System.out.println("VVVVVVVVVV="+ verifySignedObject(readSignatureKey(), signedData));
                }
//                int ch;
//                while ((ch = unc.read()) >= 0)
//                {
//                    getClearOutput().write(ch);
//                }
            }
//
//            InputStream clear = encData.getDataStream(dataDecryptorFactory);





        }
        catch(IOException | PGPOperationException e)
        {
            throw e;
        }
        catch(PGPException pgpe)
        {
            throw new PGPOperationException(pgpe.getMessage(),pgpe);
        }






















    }

    protected  boolean verifySignedObject(PGPPublicKey verifyingKey, byte[] pgpSignedData)
       throws PGPException, IOException
    {
        JcaPGPObjectFactory        pgpFact = new JcaPGPObjectFactory(pgpSignedData);

        PGPOnePassSignatureList onePassList = (PGPOnePassSignatureList)pgpFact.nextObject();
        PGPOnePassSignature ops = onePassList.get(0);

        PGPLiteralData literalData = (PGPLiteralData)pgpFact.nextObject();

        InputStream dIn = literalData.getInputStream();

        ops.init(new JcaPGPContentVerifierBuilderProvider().setProvider(new BouncyCastleProvider()), verifyingKey);

        int ch;
        while ((ch = dIn.read()) >= 0)
        {
            ops.update((byte)ch);
        }

        PGPSignatureList sigList = (PGPSignatureList)pgpFact.nextObject();
        PGPSignature sig = sigList.get(0);

        return ops.verify(sig);
    }

    private byte[] getBytesFromInputStream(InputStream is) throws IOException {
        ByteArrayOutputStream os = new ByteArrayOutputStream();
        byte[] buffer = new byte[0xFFFF];
        for (int len = is.read(buffer); len != -1; len = is.read(buffer)) {
            os.write(buffer, 0, len);
        }
        return os.toByteArray();
    }

    protected PGPPrivateKey findSecretKey(InputStream keyIn, long keyID, char[] pass)
        throws IOException, PGPOperationException
    {
        try
        {
            KeyFingerPrintCalculator calculator = new JcaKeyFingerprintCalculator();
            PGPSecretKeyRingCollection pgpSec = new PGPSecretKeyRingCollection(PGPUtil.getDecoderStream(keyIn), calculator);
            PGPSecretKey pgpSecKey = pgpSec.getSecretKey(keyID);
            PGPPrivateKey pk = null; 
            if (pgpSecKey != null)
            {
                PBESecretKeyDecryptor decryptor = new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(pass);
                pk = pgpSecKey.extractPrivateKey(decryptor);            
            }
            return(pk);
        }
        catch(IOException ioe)
        {
            throw ioe; 
        }
        catch(PGPException pgpe)
        {
            throw new PGPOperationException(pgpe.getMessage(),pgpe);
        }
    }

    public InputStream getCypherInput()
    {
        return cypherInput;
    }

    public void setCypherInput(InputStream cypherInput)
    {
        this.cypherInput = cypherInput;
    }

    public OutputStream getClearOutput()
    {
        return clearOutput;
    }

    public void setClearOutput(OutputStream clearOutput)
    {
        this.clearOutput = clearOutput;
    }

    public InputStream getPrivateKeyInput()
    {
        return privateKeyInput;
    }

    public void setPrivateKeyInput(InputStream privateKeyInput)
    {
        this.privateKeyInput = privateKeyInput;
    }

    public String getPrivateKeyPassPhrase()
    {
        return privateKeyPassPhrase;
    }

    public void setPrivateKeyPassPhrase(String privateKeyPassPhrase)
    {
        this.privateKeyPassPhrase = privateKeyPassPhrase;
    }

    public InputStream getSignatureKeyStream()
    {
        return signatureKeyStream;
    }

    public void setSignatureKeyStream(InputStream signatureKeyStream)
    {
        this.signatureKeyStream = signatureKeyStream;
    }
}