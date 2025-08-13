package ru.asmi.java_jcp_file;


import org.apache.xml.security.exceptions.AlgorithmAlreadyRegisteredException;
import org.apache.xml.security.transforms.InvalidTransformException;
import org.apache.xml.security.transforms.Transform;
import org.apache.xml.security.utils.XMLUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.reflect.Field;
import java.security.AccessController;
import java.security.PrivilegedExceptionAction;

/**
 * Сервис для инициализации XML трансформаций для СМЭВ
 */
public class XmlTransformService {
    private static final Logger logger = LoggerFactory.getLogger(XmlTransformService.class);
    
    /**
     * Инициализация СМЭВ трансформаций и настройка Apache Santuario
     * 
     * @throws IllegalStateException если инициализация не удалась
     */
    public static void initializeTransforms() throws IllegalStateException {
        try {
            logger.info("Initializing SMEV XML transforms");
            
            // Регистрация СМЭВ трансформации
            registerSmevTransform();
            
            // Настройка Apache Santuario для игнорирования переносов строк
            configureSantuarioIgnoreLineBreaks(true);
            
            logger.info("SMEV XML transforms initialized successfully");
            
        } catch (Exception e) {
            logger.error("Failed to initialize SMEV transforms", e);
            throw new IllegalStateException("SMEV transform initialization failed", e);
        }
    }
    
    /**
     * Регистрация кастомной СМЭВ трансформации
     * 
     * @throws AlgorithmAlreadyRegisteredException если алгоритм уже зарегистрирован
     * @throws InvalidTransformException если трансформация невалидна
     * @throws ClassNotFoundException если класс трансформации не найден
     */
    private static void registerSmevTransform() 
            throws AlgorithmAlreadyRegisteredException, InvalidTransformException, ClassNotFoundException {
        try {
            Transform.register(SmevTransformSpi.ALGORITHM_URN, SmevTransformSpi.class.getName());
            logger.debug("SMEV transform registered with URN: {}", SmevTransformSpi.ALGORITHM_URN);
        } catch (AlgorithmAlreadyRegisteredException e) {
            logger.warn("SMEV transform already registered: {}", e.getMessage());
            // Это не критическая ошибка - трансформация уже зарегистрирована
        }
    }
    
    /**
     * Настройка Apache Santuario для игнорирования переносов строк
     * 
     * @param ignoreLineBreaks true для игнорирования переносов строк
     */
    private static void configureSantuarioIgnoreLineBreaks(boolean ignoreLineBreaks) {
        try {
            logger.debug("Configuring Santuario ignoreLineBreaks: {}", ignoreLineBreaks);
            
            AccessController.doPrivileged(new PrivilegedExceptionAction<Boolean>() {
                @Override
                public Boolean run() throws Exception {
                    String fieldName = "ignoreLineBreaks";
                    Field field = XMLUtils.class.getDeclaredField(fieldName);
                    field.setAccessible(true);
                    field.set(null, ignoreLineBreaks);
                    return true;
                }
            });
            
            logger.debug("Santuario ignoreLineBreaks configured successfully");
            
        } catch (Exception e) {
            logger.warn("Failed to configure Santuario ignoreLineBreaks", e);
            // Это не критическая ошибка - продолжаем работу
        }
    }
    
}
