package fhw;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Iterator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.jcajce.JcaPGPObjectFactory;
import org.bouncycastle.openpgp.operator.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

public class PGPDecryptor
{

    private InputStream cypherInput;
    private OutputStream clearOutput;
    private InputStream privateKeyInput;
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
}