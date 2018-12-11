package fhw;

import org.bouncycastle.openpgp.*;
import org.bouncycastle.openpgp.operator.bc.*;
import org.bouncycastle.openpgp.operator.jcajce.JcaKeyFingerprintCalculator;

import java.io.*;
import java.util.Iterator;

public class PGPKeyUtil
{

	public static PGPPrivateKey readPrivateKey(InputStream privateSignatureKeyStream, String privateKeyPassPhrase)
		throws IOException, PGPException
	{

		PGPSecretKeyRing    sKey = new PGPSecretKeyRing(PGPUtil.getDecoderStream(privateSignatureKeyStream), new BcKeyFingerprintCalculator());
		PGPPrivateKey        pgpPrivKey = sKey.getSecretKey().extractPrivateKey(new BcPBESecretKeyDecryptorBuilder(new BcPGPDigestCalculatorProvider()).build(privateKeyPassPhrase.toCharArray()));
		return  pgpPrivKey;
	}



	public static PGPPublicKey readPublicKey(InputStream publicEncryptionKeyStream)
		throws IOException, PGPException
	{

		PGPPublicKeyRingCollection pgpPub = new PGPPublicKeyRingCollection(
			PGPUtil.getDecoderStream(publicEncryptionKeyStream),
			new JcaKeyFingerprintCalculator());
		Iterator keyRingIter = pgpPub.getKeyRings();
		while (keyRingIter.hasNext())
		{
			PGPPublicKeyRing keyRing = (PGPPublicKeyRing)keyRingIter.next();
			return keyRing.getPublicKey();
		}
		throw new IllegalArgumentException("Can't find encryption key in key ring.");
	}

}
