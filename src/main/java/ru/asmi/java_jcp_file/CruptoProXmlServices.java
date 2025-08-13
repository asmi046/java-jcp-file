package ru.asmi.java_jcp_file;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import ru.CryptoPro.Crypto.CryptoProvider;
import ru.CryptoPro.JCP.KeyStore.JCPPrivateKeyEntry;
import ru.CryptoPro.JCSP.JCSP;
import ru.CryptoPro.reprov.RevCheck;
import org.apache.xml.security.Init;

public class CruptoProXmlServices {
    private PrivateKey privateKey;
    private X509Certificate certificate;


    public CruptoProXmlServices(String alias, String password) throws KeyStoreException, NoSuchProviderException, NoSuchAlgorithmException, CertificateException, IOException, UnrecoverableEntryException  {
        
        // Установка системных свойств
        System.setProperty("file.encoding", "UTF-8");
        System.setProperty("org.apache.xml.security.ignoreLineBreaks", "true");
        System.setProperty("org.apache.xml.security.resource.config", "resource/jcp.xml");
            
        // Инициализация XML Security
        Init.init();

        Security.addProvider(new JCSP()); // провайдер JCSP
        Security.addProvider(new RevCheck()); // провайдер проверки сертификатов JCPRevCheck
        Security.addProvider(new CryptoProvider()); // провайдер шифрования JCryptoP

        XmlTransformService.initializeTransforms();

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

    public String processXmlSignature(String xmlElementID, String xmlElementName, byte[] xmlData) 
            throws Exception {
        
        
        byte[] signedXML = XMLSignatureProcessor.signXMLDocument(
            xmlData, xmlElementName, xmlElementID, 
            certificate, privateKey
        );
        
        return new String(signedXML, StandardCharsets.UTF_8);
        // XmlTemplateLoader.saveTemplate("rez", signedXMLString);
        // XmlTemplateLoader.saveTemplateToFile(outFilePath, signedXMLString);
    }

}
