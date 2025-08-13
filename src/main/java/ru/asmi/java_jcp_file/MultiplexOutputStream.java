package ru.asmi.java_jcp_file;

import java.io.IOException;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

/**
 * Вспомогательный класс для записи данных одновременно в несколько потоков вывода.
 * Используется для дублирования вывода, например, в основной поток и отладочный поток.
 */
public class MultiplexOutputStream extends OutputStream {
    
    private final List<OutputStream> streams = new ArrayList<>();
    
    /**
     * Создает MultiplexOutputStream с основным потоком вывода.
     * 
     * @param primaryStream основной поток вывода
     */
    public MultiplexOutputStream(OutputStream primaryStream) {
        if (primaryStream != null) {
            streams.add(primaryStream);
        }
    }
    
    /**
     * Добавляет дополнительный поток вывода.
     * 
     * @param stream дополнительный поток для записи
     */
    public void addOutputStream(OutputStream stream) {
        if (stream != null) {
            streams.add(stream);
        }
    }
    
    @Override
    public void write(int b) throws IOException {
        IOException lastException = null;
        for (OutputStream stream : streams) {
            try {
                stream.write(b);
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }
    
    @Override
    public void write(byte[] b) throws IOException {
        IOException lastException = null;
        for (OutputStream stream : streams) {
            try {
                stream.write(b);
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }
    
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        IOException lastException = null;
        for (OutputStream stream : streams) {
            try {
                stream.write(b, off, len);
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }
    
    @Override
    public void flush() throws IOException {
        IOException lastException = null;
        for (OutputStream stream : streams) {
            try {
                stream.flush();
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }
    
    @Override
    public void close() throws IOException {
        IOException lastException = null;
        for (OutputStream stream : streams) {
            try {
                stream.close();
            } catch (IOException e) {
                lastException = e;
            }
        }
        if (lastException != null) {
            throw lastException;
        }
    }
}
