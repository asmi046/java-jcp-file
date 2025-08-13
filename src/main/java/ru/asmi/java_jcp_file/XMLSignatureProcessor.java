package ru.asmi.java_jcp_file;

import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

import jakarta.annotation.PostConstruct;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

/**
 * Класс для создания XML подписи с использованием ГОСТ алгоритмов
 */
@Component
public class XMLSignatureProcessor {
    
    @Value("${xml.sign.namespace}")
    private String signMethodValue;
    
    @Value("${xml.hash.namespace}")
    private String digestMethodValue;
    
    @Value("${xml.canonicalization.method}")
    private  String canonicalizationMethodValue;

    private static String signMethod;
    private static String digestMethod;
    private static String canonicalizationMethod;

    @PostConstruct
    public void init() {
        signMethod = signMethodValue;
        digestMethod = digestMethodValue;
        canonicalizationMethod = canonicalizationMethodValue;
    }

    private static final String SIG_ID = "sigID";
    private static final String COULD_NOT_FIND_XML_ELEMENT_NAME = "ERROR! Could not find xmlElementName = ";
    private static final String GRID = "#";
    private static final String XML_SIGNATURE_ERROR = "xmlDSignature ERROR: ";

    /**
     * Подписывает XML документ с использованием ГОСТ алгоритмов
     *
     * @param data XML сообщение в виде массива байтов
     * @param xmlElementName имя элемента в XML вместе с префиксом, в который следует добавить подпись
     * @param xmlElementID ID элемента в XML (если присутствует) вместе с префиксом, на который следует поставить подпись
     * @param x509Cert сертификат открытого ключа проверки подписи
     * @param privateKey закрытый ключ подписи
     * @return подписанный XML документ в виде массива байтов
     * @throws SignatureProcessorException если произошла ошибка при подписании
     */
    public static byte[] signXMLDocument(byte[] data, String xmlElementName, String xmlElementID, 
                                       X509Certificate x509Cert, PrivateKey privateKey) {
        
        ByteArrayOutputStream bais = null;
        
        try {
            // инициализация объекта чтения XML-документа
            DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
            
            // установка флага, определяющего игнорирование пробелов в
            // содержимом элементов при обработке XML-документа
            dbf.setIgnoringElementContentWhitespace(true);
            
            // установка флага, определяющего преобразование узлов CDATA в
            // текстовые узлы при обработке XML-документа
            dbf.setCoalescing(true);
            
            // установка флага, определяющего поддержку пространств имен при
            // обработке XML-документа
            dbf.setNamespaceAware(true);
            
            // загрузка содержимого подписываемого документа на основе
            // установленных флагами правил из массива байтов data
            DocumentBuilder documentBuilder = dbf.newDocumentBuilder();
            Document doc = documentBuilder.parse(new ByteArrayInputStream(data));

            Element elementWithId = doc.getElementById(xmlElementID);

            if (elementWithId == null) {
                // Если не найден, попробовать найти по атрибуту
                NodeList elements = doc.getElementsByTagName("*");
                for (int i = 0; i < elements.getLength(); i++) {
                    Element el = (Element) elements.item(i);
                    if (xmlElementID.equals(el.getAttribute("Id"))) {
                        // Зарегистрировать атрибут как ID
                        el.setIdAttribute("Id", true);
                        break;
                    }
                }
            }
            
            
            String sigId = SIG_ID;
                
            // инициализация объекта формирования ЭЦП в соответствии с
            // алгоритмом ГОСТ Р 34.10-2001
            XMLSignature sig = new XMLSignature(doc, "", signMethod, canonicalizationMethod);
            
            // определение идентификатора первого узла подписи
            sig.setId(sigId);
            
            // получение корневого узла XML-документа
            Element anElement = null;
            if (xmlElementName == null) {
                anElement = doc.getDocumentElement();
            } else {
                NodeList nodeList = doc.getElementsByTagName(xmlElementName);
                if (nodeList.getLength() > 0) {
                    anElement = (Element) nodeList.item(0);
                }
            }
            
            // добавление в корневой узел XML-документа узла подписи
            if (anElement != null) {
                anElement.appendChild(sig.getElement());
            } else {
                throw new IllegalArgumentException(COULD_NOT_FIND_XML_ELEMENT_NAME + xmlElementName);
            }
            
            /*
             * Определение правил работы с XML-документом и добавление в узел подписи этих
             * правил
             */
            
            // создание узла преобразований <ds:Transforms> обрабатываемого
            // XML-документа
            Transforms transforms = new Transforms(doc);
            
            // добавление в узел преобразований правил работы с документом
            transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
            transforms.addTransform(SmevTransformSpi.ALGORITHM_URN);
            
            // добавление в узел подписи ссылок (узла <ds:Reference>),
            // определяющих правила работы с
            // XML-документом (обрабатывается текущий документ с заданными в
            // узле <ds:Transforms> правилами
            // и заданным алгоритмом хеширования)
            sig.addDocument(xmlElementID == null ? "" : GRID + xmlElementID, transforms, digestMethod);
            
            /*
             * Создание подписи всего содержимого XML-документа на основе закрытого ключа,
             * заданных правил и алгоритмов
             */
            
            // создание внутри узла подписи узла <ds:KeyInfo> информации об
            // открытом ключе на основе сертификата
            sig.addKeyInfo(x509Cert);
            
            // создание подписи XML-документа
            sig.sign(privateKey);
        
            // определение потока, в который осуществляется запись подписанного
            // XML-документа
            bais = new ByteArrayOutputStream();
            
            // инициализация объекта копирования содержимого XML-документа в
            // поток
            TransformerFactory tf = TransformerFactory.newInstance();
            
            // создание объекта копирования содержимого XML-документа в поток
            Transformer trans = tf.newTransformer();
            
            // копирование содержимого XML-документа в поток
            trans.transform(new DOMSource(doc), new StreamResult(bais));
            bais.close();

        } catch (Exception e) {
            throw new RuntimeException("RuntimeException " + XML_SIGNATURE_ERROR + e.getMessage(), e);
        } 
        
        return bais.toByteArray();
    }
}
