package com.p3solutions.archon_authentication_service.core.configuration.logback;

import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.joran.JoranConfigurator;
import ch.qos.logback.classic.util.ContextInitializer;
import com.p3solutions.common_beans_dto.administration.abstract_repository.AdministrationConfigAbstractRepository;
import com.p3solutions.common_beans_dto.administration.beans.RetentionConfig;
import com.p3solutions.common_beans_dto.administration.enums.RecordType;
import com.p3solutions.common_beans_dto.administration.mapper_beans.AdministrationConfigMapperBean;
import com.p3solutions.utility.common_exceptions.ExceptionHandler;
import lombok.extern.slf4j.Slf4j;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.util.CollectionUtils;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;

/**
 * @author Chetana patil
 */

@Component("logBackConfiguration")
@Slf4j
public class LogBackConfiguration {

    @Autowired
    private AdministrationConfigAbstractRepository administrationConfigAbstractRepository;

    @Value(value = "${spring.application.name}")
    private String appName;

    @Value(value = "${customlog.path}")
    private String logPath;

    private String LOGBACK_FILEPATH;
    @Value(value = "${customlog.profile}")
    private String profile;

    @Bean
    CommandLineRunner initLogBackFile() {
        return args -> {
            loadAndSaveLogBackIncludeFile();
        };
    }
    /*
     *  Load and save the logback included file
     *
     *  @Author Chetana patil
     */
    public void loadAndSaveLogBackIncludeFile() throws Exception {
        String fileName = "LogbackReloadContent.txt";
        File logBackIncludedFile;
        try {
            buildDirForLog();
            checkCreateDirectory(logPath+File.separator+appName+File.separator+"config");
            logBackIncludedFile = new File(LOGBACK_FILEPATH);
        } catch (Exception e) {
            ExceptionHandler.exception(e.getMessage(),e);
            return;
        }
        if (logBackIncludedFile.exists()) {
            fetchAdministrationLogValue();
            return;
        }
        PrintWriter printWriter = new PrintWriter(logBackIncludedFile);
        InputStream inputStream = fetchFileResourceAsStream(fileName);
        writeDataIntoIncludedFile(inputStream, printWriter);
        printWriter.close();
        if (logBackIncludedFile.exists()) {
            fetchAdministrationLogValue();
        }
        if(profile.equalsIgnoreCase("LOGGER_STD_FILE")) {
            reloadLogger();
        }
    }

    /*
     *  Update the max history value from taking from UI.
     *
     *  @Author Chetana patil
     */

    public void updateLogBackConfig(RetentionConfig retentionConfig) throws Exception {
        buildDirForLog();
        String filePath = LOGBACK_FILEPATH;
        File configurationFile = new File(filePath);
        if(configurationFile.exists()) {
            DocumentBuilderFactory docFactory = DocumentBuilderFactory.newInstance();
            docFactory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
            docFactory.setFeature("http://xml.org/sax/features/external-general-entities", false);
            docFactory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
            DocumentBuilder docBuilder = docFactory.newDocumentBuilder();
            Document doc = docBuilder.parse(configurationFile);
            NodeList appenderList = doc.getElementsByTagName("appender");
            for (int i = 0; i < appenderList.getLength(); i++) {
                Element appender = (Element) appenderList.item(i);
                if (appender.getAttributes().getNamedItem("name").getTextContent().startsWith("ROLLING")) {
                    if (!Objects.isNull(retentionConfig)) {
                        Node node = appender.getElementsByTagName("maxHistory").item(0);
                        node.setTextContent(retentionConfig.getDataBackupPolicy() + "");
                    }
                }
            }
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            Transformer transformer = transformerFactory.newTransformer();
            DOMSource source = new DOMSource(doc);
            StreamResult result = new StreamResult(new File(filePath));
            transformer.transform(source, result);
        }
    }

    /*
     *  Fetch the file resource data as stream
     *
     *  @Author Chetana patil
     */
    private InputStream fetchFileResourceAsStream(String fileName) {
        ClassLoader classLoader = getClass().getClassLoader();
        InputStream inputStream = classLoader.getResourceAsStream(fileName);
        if (inputStream == null) {
            log.info("Log back file is empty");
            return null;
        } else {
            return inputStream;
        }

    }

    /*
     *  Write data into the specified file
     *  @Author Chetana patil
     */
    private void writeDataIntoIncludedFile(InputStream is, PrintWriter printWriter) {
        try (InputStreamReader streamReader = new InputStreamReader(is, StandardCharsets.UTF_8);
             BufferedReader reader = new BufferedReader(streamReader)) {
            String line;
            while ((line = reader.readLine()) != null) {
                printWriter.write(line + "\n");
            }
        } catch (IOException e) {
            ExceptionHandler.exception(e.getMessage(),e);
        }
    }
    /*
     *  reload the logger file
     *  @Author Chetana patil
     */
    private void reloadLogger() {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        URL url = getClass().getClassLoader().getResource("logback-spring.xml");
        try {
            JoranConfigurator configurator = new JoranConfigurator();
            configurator.setContext(loggerContext);
            configurator.doConfigure(url);
           // loggerContext.reset();
        } catch (Exception e) {
            ExceptionHandler.exception(e.getMessage(),e);
        }
    }
    /*
     * While reloading logger file , fetch the logger history from Database and update into xml file
     *  @Author Chetana patil
     */
    private void fetchAdministrationLogValue() throws Exception {
        List<AdministrationConfigMapperBean> administrationConfigMapperBeans =  administrationConfigAbstractRepository.findAll();
        if(!CollectionUtils.isEmpty(administrationConfigMapperBeans)){
            AdministrationConfigMapperBean administrationConfigMapperBean = administrationConfigMapperBeans.get(0);
            Integer logValue = administrationConfigMapperBean.getDataBackupPolicy().get(RecordType.LOG);
            RetentionConfig retentionConfig = RetentionConfig.builder().dataBackupPolicy(logValue).build();
            updateLogBackConfig(retentionConfig);
        }
    }

    public void checkCreateDirectory(String fileDir) throws Exception {
        if (!checkForDirectory(fileDir)) {
            createDir(fileDir);
        }
    }
    public static boolean checkForDirectory(String fileDir) throws Exception {
        File f;
        try {
            f = new File(fileDir);
            return f.isDirectory();
        } finally {
            f = null;
        }
    }
    public static File createDir(String dir) throws IOException {
        File tmpDir = new File(dir);
        if (!tmpDir.exists()) {
            if (!tmpDir.mkdirs()) {
                throw new IOException("Could not create temporary directory: " + tmpDir.getAbsolutePath());
            }
        }
        return tmpDir;
    }

    private void buildDirForLog(){
        LOGBACK_FILEPATH = logPath+ File.separator+appName+File.separator+"config"+File.separator+"logback-included.xml";
    }


}
