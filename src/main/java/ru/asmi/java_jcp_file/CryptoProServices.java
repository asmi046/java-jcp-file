package ru.asmi.java_jcp_file;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.Signature;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Arrays;


import com.objsys.asn1j.runtime.Asn1BerDecodeBuffer;
import com.objsys.asn1j.runtime.Asn1BerEncodeBuffer;
import com.objsys.asn1j.runtime.Asn1Null;
import com.objsys.asn1j.runtime.Asn1ObjectIdentifier;

import ru.CryptoPro.JCP.JCP;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CMSVersion;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateChoices;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.CertificateSet;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.ContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.DigestAlgorithmIdentifiers;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.EncapsulatedContentInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.IssuerAndSerialNumber;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureAlgorithmIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignatureValue;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignedData;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerIdentifier;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfo;
import ru.CryptoPro.JCP.ASN.CryptographicMessageSyntax.SignerInfos;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.CertificateSerialNumber;
import ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Name;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCP.params.OID;
import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.reprov.RevCheck;


public class CryptoProServices {
    private PrivateKey privateKey;
    private X509Certificate certificate;

    // final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.9.3";
    final String STR_CMS_OID_SIGNED = "1.2.840.113549.1.7.2";
    final String STR_CMS_OID_DATA = "1.2.840.113549.1.7.1";

    public CryptoProServices(String alias, String password) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException  {
        Security.addProvider(new JCSP()); // провайдер JCSP
        Security.addProvider(new RevCheck()); // провайдер проверки сертификатов JCPRevCheck
        Security.addProvider(new CryptoProvider()); // провайдер шифрования JCryptoP

        KeyStore ks = KeyStore.getInstance("HDIMAGE", "JCSP");
        ks.load(null, null);

        KeyStore.ProtectionParameter params = new KeyStore.PasswordProtection(password.toCharArray());
        JCPPrivateKeyEntry entry = (JCPPrivateKeyEntry) ks.getEntry(alias, params);

        if (entry == null) {
                throw new KeyStoreException("Private key not found for alias: " + alias, null);
        }
            
        privateKey = entry.getPrivateKey();

        certificate = (X509Certificate) ks.getCertificate(alias);

        if (certificate == null) {
                throw new KeyStoreException("Certificate not found for alias: " + alias, null);
        }
    }

    public byte[] signDataRaw(byte[] data) throws Exception {
        if (privateKey == null || certificate == null) {
            throw new IllegalStateException("Private key or certificate not initialized");
        }

        Signature sig = Signature.getInstance("GOST3411_2012_256withGOST3410_2012_256", "JCSP");
        sig.initSign(privateKey);
        sig.update(data);
        return sig.sign();
    }


    public byte[] signByteArray(byte[] data) throws Exception {

        ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(new OID(STR_CMS_OID_SIGNED).value);
        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(4);
        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(new DigestAlgorithmIdentifier[]{new DigestAlgorithmIdentifier(new OID(JCP.GOST_DIGEST_OID).value)});
        cms.encapContentInfo = new EncapsulatedContentInfo(
                new Asn1ObjectIdentifier(
                        new OID(STR_CMS_OID_DATA).value),
                null);
        X509Certificate cert = certificate;

        cms.certificates = new CertificateSet(1);

        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate asnCertificate =
            new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();

        final Asn1BerDecodeBuffer decodeBuffer =
            new Asn1BerDecodeBuffer(certificate.getEncoded());
        asnCertificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(asnCertificate);

        byte[] sign;
        java.security.Signature signature = java.security.Signature.getInstance(JCP.GOST_SIGN_2012_256_NAME);
        signature.initSign(privateKey);

        signature.update(data);
        sign = signature.sign();

        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1); //because of issuerAndSerialNumber. More: rfc.3852, p.13.
        cms.signerInfos.elements[0].sid = new SignerIdentifier();
        final byte[] encodedName = cert.getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(cert.getSerialNumber());
        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm = new DigestAlgorithmIdentifier(new OID(JCP.GOST_DIGEST_2012_256_OID).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm = new SignatureAlgorithmIdentifier(new OID(JCP.GOST_PARAMS_SIG_2012_256_KEY_OID).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();

        cms.signerInfos.elements[0].signature = new SignatureValue(sign);
        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);
        return asnBuf.getMsgCopy();
    }

    /**
     * Функция формирования простой отсоединенной подписи формата PKCS#7
     * по хешу сообщения.
     * Пример подписи взят из {@link CMS_samples.CMS#CMSSign(byte[],
     * PrivateKey, Certificate, boolean)}.
     *
     * @param data Данные для подписи.
     * @param privateKey Закрытый ключ для создания ЭЦП.
     * @param certificate Сертификат подписи.
     * @return ЭЦП.
     * @throws Exception
     */
    public byte[] createPKCS7(byte[] data) throws Exception {

        // Получаем бинарную подпись длиной 64 байта.

        final Signature signature = Signature.getInstance(JCP.GOST_SIGN_2012_256_NAME);
        signature.initSign(privateKey);
        signature.update(data);

        final byte[] sign = signature.sign();

        // Формируем контекст подписи формата PKCS7.

        final ContentInfo all = new ContentInfo();
        all.contentType = new Asn1ObjectIdentifier(
            new OID(STR_CMS_OID_SIGNED).value);

        final SignedData cms = new SignedData();
        all.content = cms;
        cms.version = new CMSVersion(1);

        // Идентификатор алгоритма хеширования.

        cms.digestAlgorithms = new DigestAlgorithmIdentifiers(1);
        final DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
            new OID(JCP.GOST_DIGEST_2012_256_OID).value);
        a.parameters = new Asn1Null();
        cms.digestAlgorithms.elements[0] = a;

        // Т.к. подпись отсоединенная, то содержимое отсутствует.

        cms.encapContentInfo = new EncapsulatedContentInfo(
            new Asn1ObjectIdentifier(new OID(STR_CMS_OID_DATA).value), null);

        // Добавляем сертификат подписи.

        cms.certificates = new CertificateSet(1);
        final ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate asnCertificate =
            new ru.CryptoPro.JCP.ASN.PKIX1Explicit88.Certificate();

        final Asn1BerDecodeBuffer decodeBuffer =
            new Asn1BerDecodeBuffer(certificate.getEncoded());
        asnCertificate.decode(decodeBuffer);

        cms.certificates.elements = new CertificateChoices[1];
        cms.certificates.elements[0] = new CertificateChoices();
        cms.certificates.elements[0].set_certificate(asnCertificate);

        // Добавялем информацию о подписанте.

        cms.signerInfos = new SignerInfos(1);
        cms.signerInfos.elements[0] = new SignerInfo();
        cms.signerInfos.elements[0].version = new CMSVersion(1);
        cms.signerInfos.elements[0].sid = new SignerIdentifier();

        final byte[] encodedName = certificate.getIssuerX500Principal().getEncoded();
        final Asn1BerDecodeBuffer nameBuf = new Asn1BerDecodeBuffer(encodedName);
        final Name name = new Name();
        name.decode(nameBuf);

        final CertificateSerialNumber num = new CertificateSerialNumber(
            certificate.getSerialNumber());

        cms.signerInfos.elements[0].sid.set_issuerAndSerialNumber(
            new IssuerAndSerialNumber(name, num));
        cms.signerInfos.elements[0].digestAlgorithm =
            new DigestAlgorithmIdentifier(new OID(JCP.GOST_DIGEST_2012_256_OID).value);
        cms.signerInfos.elements[0].digestAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signatureAlgorithm =
            new SignatureAlgorithmIdentifier(new OID(JCP.GOST_PARAMS_SIG_2012_256_KEY_OID).value);
        cms.signerInfos.elements[0].signatureAlgorithm.parameters = new Asn1Null();
        cms.signerInfos.elements[0].signature = new SignatureValue(sign);

        // Получаем закодированную подпись.

        final Asn1BerEncodeBuffer asnBuf = new Asn1BerEncodeBuffer();
        all.encode(asnBuf, true);

        return asnBuf.getMsgCopy();
    }

     /**
     * Функция декодирования подписи формата PKCS7.
     * Пример подписи взят из {@link CMS_samples.CMS#CMSVerify(byte[],
     * Certificate, byte[])}.
     *
     * @param pkcs7Signature ЭЦП формата PKCS7.
     * @param data Подписанные данные.
     * @param certificate Сертификат для проверки подписи.
     * @return True, если подпись корректна.
     * @throws Exception
     */
    public boolean verifyPKCS7(byte[] pkcs7Signature, byte[] data) throws Exception {

        // Декодирование подписи формата PKCS7.

        int i = -1;
        final Asn1BerDecodeBuffer asnBuf = new Asn1BerDecodeBuffer(pkcs7Signature);
        final ContentInfo all = new ContentInfo();
        all.decode(asnBuf);

        // Проверка формата подписи.

        boolean supportedType =
            new OID(STR_CMS_OID_SIGNED).eq(all.contentType.value);
        if (!supportedType) {
            throw new Exception("Not supported");
        }

        final SignedData cms = (SignedData) all.content;

        if (cms.version.value != 1) {
            throw new Exception("Incorrect version");
        }

        boolean supportedData = new OID(STR_CMS_OID_DATA).eq(
            cms.encapContentInfo.eContentType.value);
        if (!supportedData) {
            throw new Exception("Nested not supported");
        }

        byte[] text = null;
        if (data != null) {
            text = data;
        } else if (cms.encapContentInfo.eContent != null) {
            text = cms.encapContentInfo.eContent.value;
        }

        if (text == null) {
            throw new Exception("No content");
        }

        // Получение идентификатора алгоритма хеширования.

        OID digestOid = null;
        DigestAlgorithmIdentifier a = new DigestAlgorithmIdentifier(
            new OID(JCP.GOST_DIGEST_2012_256_OID).value);

        for (i = 0; i < cms.digestAlgorithms.elements.length; i++) {

            if (cms.digestAlgorithms.elements[i].algorithm.equals(a.algorithm)) {
                digestOid = new OID(cms.digestAlgorithms.elements[i].algorithm.value);
                break;
            } // if

        } // for

        if (digestOid == null) {
            throw new Exception("Unknown digest");
        }

        // Поиск сертификат подписи.

        int pos = -1;
        for (i = 0; i < cms.certificates.elements.length; i++) {

            final Asn1BerEncodeBuffer encBuf = new Asn1BerEncodeBuffer();
            cms.certificates.elements[i].encode(encBuf);

            final byte[] in = encBuf.getMsgCopy();
            if (Arrays.equals(in, certificate.getEncoded())) {
                System.out.println("Selected certificate: " + certificate.getSubjectDN());
                pos = i;
                break;
            } // if

        } // for

        if (pos == -1) {
            throw new Exception("Not signed on certificate");
        }

        // Декодирование подписанта.

        final SignerInfo info = cms.signerInfos.elements[pos];
        if (info.version.value != 1) {
            throw new Exception("Incorrect version");
        }

        if (!digestOid.equals(new OID(info.digestAlgorithm.algorithm.value))) {
            throw new Exception("Not signed on certificate");
        }

        final byte[] sign = info.signature.value;

        // Проверка подписи.

        // final Signature signature = Signature.getInstance(JCP.GOST_PARAMS_SIG_2012_256_KEY_OID);
        final Signature signature = Signature.getInstance(JCP.GOST_SIGN_2012_256_NAME);
        signature.initVerify(certificate);
        signature.update(text);

        return signature.verify(sign);
    }
}
