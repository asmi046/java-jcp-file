package ru.asmi.java_jcp_file;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
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

	@Value("${sign.alias}")
	private String signAlias;

	@Value("${sign.password}")
	private String signPassword;

    @PostMapping(value = "/sign", produces = "application/pkcs7-signature")
	@ResponseBody
    public ResponseEntity<?> calculateChecksum(@RequestParam("file") MultipartFile file) throws IOException, NoSuchAlgorithmException {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error: File is empty");
        }

		try {
			CryptoProServices cryptoProServices = new CryptoProServices(signAlias, signPassword);
			byte[] pkcs7Bytes = cryptoProServices.createPKCS7(file.getBytes());
			return ResponseEntity.ok(pkcs7Bytes);

		}  catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
		}

    }
    
    @PostMapping(value = "/digest", produces = "application/octet-stream")
	@ResponseBody
    public ResponseEntity<?> calculateDigest(@RequestParam("file") MultipartFile file) throws IOException, NoSuchAlgorithmException {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).body("Error: File is empty");
        }

		try {
			CryptoProServices cryptoProServices = new CryptoProServices(signAlias, signPassword);
			byte[] digest = cryptoProServices.digestDataRaw(file.getBytes());
			return ResponseEntity.ok(digest);

		}  catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
		}

    }


	@PostMapping(value = "/sign_xml", produces = "application/xml")
    @ResponseBody
    public ResponseEntity<?> signXml(
            @RequestParam("file") MultipartFile file,
            @RequestParam("elementId") String elementId,
            @RequestParam("signatureElementName") String signatureElementName) {

        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).body("<error>File is empty</error>");
        }

        try {
            CruptoProXmlServices cryptoProXmlServices = new CruptoProXmlServices(signAlias, signPassword);

			String signedXml = cryptoProXmlServices.processXmlSignature(elementId, signatureElementName, file.getBytes());

            return ResponseEntity.ok(signedXml);

        } catch (Exception e) {
            e.printStackTrace();
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("<error>" + e.getMessage() + "</error>");
        }
    }

    
	@PostMapping(value = "/verify")
	@ResponseBody
    public ResponseEntity<?> verifyChecksum(@RequestParam("file") MultipartFile file, @RequestParam("signature") MultipartFile signature) throws IOException, NoSuchAlgorithmException {
        if (file.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).body("Error: File is empty");
        }
        if (signature.isEmpty()) {
            return ResponseEntity.status(HttpStatus.NO_CONTENT).body("Error: Signature is empty");
        }

		try {
			CryptoProServices cryptoProServices = new CryptoProServices(signAlias, signPassword);

			boolean verified = cryptoProServices.verifyPKCS7(signature.getBytes(), file.getBytes());
			return ResponseEntity.ok(verified);

		}  catch (Exception e) {
			e.printStackTrace();
			return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error: " + e.getMessage());
		}
    }

	@GetMapping("/")
    public String serviceInfo() {
        return "info";
    }
}
