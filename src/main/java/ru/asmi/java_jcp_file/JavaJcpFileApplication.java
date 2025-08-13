package ru.asmi.java_jcp_file;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.UnrecoverableEntryException;
import java.security.cert.CertificateException;


import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.bind.annotation.GetMapping;

@SpringBootApplication
public class JavaJcpFileApplication {

	public static void main(String[] args) {
		SpringApplication.run(JavaJcpFileApplication.class, args);
	}

}

@Controller
@RequestMapping("/api")
class FileChecksumController {

    @PostMapping(value = "/checksum", produces = "application/pkcs7-signature")
	@ResponseBody
    public byte[] calculateChecksum(@RequestParam("file") MultipartFile file) throws IOException, NoSuchAlgorithmException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }

		try {
			CryptoProServices cryptoProServices = new CryptoProServices("qonnfw1l", "7pchnyy6");
			// return cryptoProServices.signDataRaw(file.getBytes());

			// Сохраняем результат в файл
			byte[] pkcs7Bytes = cryptoProServices.createPKCS7(file.getBytes());
			// byte[] pkcs7Bytes = cryptoProServices.signByteArray(file.getBytes());
			java.nio.file.Files.write(java.nio.file.Paths.get("1.txt.p7s"), pkcs7Bytes);

			return pkcs7Bytes;

		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableEntryException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
    }
    
	@PostMapping(value = "/verify")
	@ResponseBody
    public boolean verifyChecksum(@RequestParam("file") MultipartFile file, @RequestParam("signature") MultipartFile signature) throws IOException, NoSuchAlgorithmException {
        if (file.isEmpty()) {
            throw new IllegalArgumentException("File is empty");
        }
        if (signature.isEmpty()) {
            throw new IllegalArgumentException("Signature is empty");
        }

		try {
			CryptoProServices cryptoProServices = new CryptoProServices("qonnfw1l", "7pchnyy6");
			// return cryptoProServices.signDataRaw(file.getBytes());

			// Сохраняем результат в файл
			boolean verified = cryptoProServices.verifyPKCS7(signature.getBytes(), file.getBytes());

			return verified;

		} catch (KeyStoreException | NoSuchProviderException | NoSuchAlgorithmException | CertificateException
				| UnrecoverableEntryException | IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return false;
    }

	@GetMapping("/")
    public String serviceInfo() {
        return "info";
    }
}
