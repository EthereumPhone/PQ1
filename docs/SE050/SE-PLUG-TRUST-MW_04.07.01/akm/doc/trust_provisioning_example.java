
/* Copyright 2019 NXP
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/* doc:start:RSA-TP-example */
PrivateKey ImportTPKeyRSA() throws NoSuchAlgorithmException,
		InvalidKeySpecException
{
	PrivateKey privKey;
	KeyFactory KeyFac;
	BigInteger Mod, PrivExp, PubExp, PrimeP, PrimeQ, PrimeExpP, PrimeExpQ, CrtCoef;
	RSAPrivateCrtKeySpec spec;
	try {
		KeyFac = KeyFactory.getInstance("RSA");
	} catch (NoSuchAlgorithmException e) {
		throw e;
	}
	Random rnd = new Random();
	StringBuffer temp = new StringBuffer(112);
	for(int i=0 ; i<112 ; i++)
	{
		int val = rnd.nextInt(16);
		temp.append(Integer.toString(val, 16));
	}
	StringBuffer buf = new StringBuffer(128);
	String mag = "a5a6b5b6a5a6b5b6";
	buf.append(mag);
	buf.append(temp);
	String mod = buf.toString();

	Mod = new BigInteger(mod, 16);
	PrivExp = new BigInteger("A523006702", 16);	//KeyID in hex at which Trust provisioned key is stored
	PubExp = new BigInteger("65537");
	PrimeP = new BigInteger("1");
	PrimeQ = new BigInteger("1");
	PrimeExpP = new BigInteger("1");
	PrimeExpQ = new BigInteger("1");
	CrtCoef = new BigInteger("1");

	// Create a RSA private key spec using components which have the magic and keyID
	spec = new RSAPrivateCrtKeySpec(Mod, PubExp, PrivExp, PrimeP, PrimeQ, PrimeExpP, PrimeExpQ, CrtCoef);

	try {
		// Generate a dummy keypair using key factory which will be in the desired format to export trust provisioned keypair
		privKey = KeyFac.generatePrivate(spec);
	} catch (InvalidKeySpecException e) {
		throw e;
	}

	return privKey;
}


void SetTPKeyRSA(String Label) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException,
			CertificateException
{
	PrivateKey privKey;
	X509Certificate cCert;
	// Dummy RSA certificate to create a keystore entry
	final String cDummyCert = "-----BEGIN CERTIFICATE-----\nMIIB9zCCAWCgAwIBAgIEITKMnTANBgkqhkiG9w0BAQsFADA3MRgwFgYDVQQDEw9JbnRlcm5hbFVzZU9ubHkxGzAZBgNVBAUTEjAyNDk5OTkwMDAwMDAwMDAwMTAeFw0xNzA4MjUwNzIyMDVaFw0zMjA4MjUwNzIyMDVaMDcxGDAWBgNVBAMTD0ludGVybmFsVXNlT25seTEbMBkGA1UEBRMSMDI0OTk5OTAwMDAwMDAwMDAxMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQCE+95LNOSG03eAyk5bRC0KvbJVZIw0Ru2jpQyGX1D1ASnPjD4InQLPg9qIvSz3U7m84PR5WLexq+wyUiraMeWpXBlLn8FVQoKNidMF+DhK7TaGWK2oMHFK/s14cnwE1/5Te5uunM7li2NPphTjbUMrUH7Du+t/EWb0UdHN4mGKKQIDAQABoxAwDjAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUAA4GBAAGmSkfLAVijSRRTAdPhqxk0ifNYDJRAqoJNrxiBN2pvsaUFyo8kde7MhCnNNsHZStf8ZdIztKb6G9Lt8HjYmsI6+fCqHxYjEeFcCVc5Vzg5SpzdtxzYLhEwRYLs0Dzv3rSYPXcN475eFQbH83/0tCuGuc3XcbvXjNhdddoZdvNg\n-----END CERTIFICATE-----";

	try
	{
		privKey = ImportTPKeyRSA();
	}
	catch (Exception e)
	{
		throw e;
	}

	Certificate[] aUseCert;
	aUseCert = new X509Certificate[1];
	CertificateFactory cCertFac;
	InputStream in = new ByteArrayInputStream(cDummyCert.getBytes());
	try {
		cCertFac = CertificateFactory.getInstance("X.509");
	} catch (CertificateException e) {
		throw e;
	}
	aUseCert[0] = (X509Certificate) cCertFac.generateCertificate(in);

	try
	{
		// Store the keypair in keystore with alias=Label and dummy certificate chain = aUseCert
		m_cKeyStore.setKeyEntry(Label,(Key) privKey,null ,aUseCert);
	}
	catch (KeyStoreException e)
	{
		throw e;
	}
	return;
}
/* doc:end:RSA-TP-example */

/* doc:start:EC-TP-example */
ECPrivateKey ImportTPKeyECC() throws NoSuchAlgorithmException,
		InvalidKeySpecException,
		InvalidParameterSpecException,
		InvalidAlgorithmParameterException, NoSuchProviderException
{
	ECPrivateKey privKey;
	KeyFactory KeyFac;
	BigInteger PrivS;
	ECParameterSpec ECSpec;
	ECPrivateKeySpec PrivSpec;
	Random rnd = new Random();

	StringBuffer temp = new StringBuffer(40);
	for(int i=0 ; i<40 ; i++)
	{
		int val = rnd.nextInt(16);
		temp.append(Integer.toString(val, 16));
	}

	StringBuffer buf = new StringBuffer(64);
	String mag = "a5a6b5b6a5a6b5b6";
	String keyobject = "c3020001";
	buf.append(mag);
	buf.append(keyobject);
	buf.append(temp);
	String magic = buf.toString();
	PrivS = new BigInteger(magic, 16);
	String cECCCurveName = "secp256r1";
	AlgorithmParameters algSpec = AlgorithmParameters.getInstance("EC");

	try {
		algSpec.init(new ECGenParameterSpec(cECCCurveName));
	} catch (InvalidParameterSpecException e1) {
		e1.printStackTrace();
	}

	ECSpec = algSpec.getParameterSpec(ECParameterSpec.class);
	// Create PrivateKey spec with parameters for curve secp256r1 and private key containing the magic and the keyID
	PrivSpec = new ECPrivateKeySpec(PrivS, ECSpec);

	try {
		KeyFac = KeyFactory.getInstance("EC");
	} catch (NoSuchAlgorithmException e) {
		throw e;
	}

	try {
		// Generate a dummy keypair using key factory which will be in the desired format to export trust provisioned keypair
		privKey = (ECPrivateKey) KeyFac.generatePrivate(PrivSpec);
	} catch (InvalidKeySpecException e) {
		throw e;
	}

	return privKey;
}


void SetTPKeyEC(String Label) throws NoSuchAlgorithmException, InvalidKeySpecException, KeyStoreException,
		CertificateException, GeneralSecurityException {
	ECPrivateKey privKey;
	X509Certificate cCert;
	final String cDummyCert = "-----BEGIN CERTIFICATE-----\n" +
			"MIIBeTCCASCgAwIBAgIJAKtU6mCCLJeyMAoGCCqGSM49BAMCMBExDzANBgNVBAMMBmRlbW9DQTAeFw0xOTA1MDMxNDQyNDVaFw0yNzAxMDExNDQyNDVaMBExDzANBgNVBAMMBmRlbW9DQTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABKFlRck++xuGvo9FnFp7Tp0vA+xrZ0oIy2bsuzFrlVCZt7J00B2E+kxMFPCISi/wC3xvYYQv6o7l16kcQxw9CByjYTBfMAwGA1UdEwQFMAMBAf8wTwYDVR0RBEgwRoEmZDpOWFAtQTcxQ0gtRDozNzc4MTM0MjYzNzg2MDcxOTY4OTcyNzmGHE5YUDozNzc4MTM0MjYzNzg2MDcxOTY4OTcyNzkwCgYIKoZIzj0EAwIDRwAwRAIgC9849zJCRndqkGMgHYZqq/63cSGmmwlnw6H8eVaNqUwCIESKl/PAkaVE/u/o5a1v4hJ7jLH06NvdaatTINz0umK/\n-----END CERTIFICATE----- ";

	privKey = ImportTPKeyECC();

	Certificate[] aUseCert;
	aUseCert = new X509Certificate[1];
	CertificateFactory cCertFac;
	InputStream in = new ByteArrayInputStream(cDummyCert.getBytes());

	try {
		cCertFac = CertificateFactory.getInstance("X.509");
	} catch (CertificateException e) {
		throw e;
	}
	aUseCert[0] = (X509Certificate) cCertFac.generateCertificate(in);

	try
	{
		// Store the keypair in keystore with alias=Label and dummy certificate chain = aUseCert
		m_cKeyStore.setKeyEntry(Label,(Key) privKey,null ,aUseCert);
	}
	catch (KeyStoreException e)
	{
		throw e;
	}

	return;
}
/* doc:end:EC-TP-example */

