package com.uqac.bruteforce_ssh.services;


import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.uqac.bruteforce_ssh.dto.ApiProperties;
import com.uqac.bruteforce_ssh.dto.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.ResourceAccessException;
import org.springframework.web.client.RestTemplate;

import java.io.*;
import java.nio.file.Files;
import java.util.Collections;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CppExecutionService {

    @Autowired
    private ApiProperties apiProperties;


    /**
     * Logger
     */
    private static final Logger logger = LoggerFactory.getLogger(CppExecutionService.class);

    // Map pour stocker l'état du scan (clé = scanId)
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();

    /**
     * Exécute le programme C++ de scan de ports
     *
     * @param reportId Identifiant du rapport
     * @param ip       Adresse IP à scanner
     * @param scanId   Identifiant du scan
     */
    @Async
    public void executeCppProgram(Long reportId, String ip, String scanId) {
        try {
            logger.info("Executing cpp program {} {} {}", reportId, ip, scanId);
            scanStatus.put(scanId, "IN_PROGRESS");

            // Extraire le fichier sshConnexion
            InputStream sshConnexionStream = getClass().getResourceAsStream("/cppSSHAttack/sshConnexion");
            File sshConnexionFile = Files.createTempFile("sshConnexion", "").toFile();
            assert sshConnexionStream != null;
            extractFile(sshConnexionStream, sshConnexionFile);
            sshConnexionFile.setExecutable(true);

            // Extraire le fichier wordList_ssh_hydra.txt
            InputStream wordListStream = getClass().getResourceAsStream("/cppSSHAttack/wordList_ssh_hydra.txt");
            File wordListFile = Files.createTempFile("wordList_ssh_hydra", ".txt").toFile();
            assert wordListStream != null;
            extractFile(wordListStream, wordListFile);

            // Exécuter le fichier temporaire
            ProcessBuilder processBuilder = new ProcessBuilder(sshConnexionFile.getAbsolutePath(), reportId + "", ip, wordListFile.getAbsolutePath());
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();

            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\n");
            }

            int exitCode = process.waitFor();
            if (exitCode == 0) {
                logger.info("Scan terminé pour IP {} : {}", ip, result);
                scanStatus.put(scanId, "COMPLETED: " + result.toString());
            } else {
                logger.error("Erreur lors de l'exécution du scan : {}", result);
                scanStatus.put(scanId, "ERROR: Exit code " + exitCode + " : " + result.toString());
            }

            callExternalService(scanId, result);

        } catch (Exception e) {
            scanStatus.put(scanId, "EXCEPTION: " + e.getMessage());
            logger.error("Erreur lors de l'exécution du scan", e);
        }
    }

    /**
     * Extrait le fichier sshConnexion
     *
     * @param sshConnexionStream flux d'entrée du fichier sshConnexion
     * @param sshConnexionFile   fichier temporaire
     * @throws IOException erreur d'entrée/sortie
     */
    private void extractFile(InputStream sshConnexionStream, File sshConnexionFile) throws IOException {
        try (FileOutputStream outputStream = new FileOutputStream(sshConnexionFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while (true) {
                assert sshConnexionStream != null;
                if ((bytesRead = sshConnexionStream.read(buffer)) == -1) break;
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    /**
     * Appelle un service externe pour envoyer le résultat du scan
     *
     * @param scanId Identifiant du scan
     * @param result Résultat du scan
     * @throws JsonProcessingException Erreur de traitement JSON
     */
    private void callExternalService(String scanId, StringBuilder result) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        ScanResult scanResult = objectMapper.readValue(result.toString(), ScanResult.class);

        logger.info(scanResult.toString());

        RestTemplate restTemplate = new RestTemplate();
        String externalServiceUrl = apiProperties.getUrl()
                + "/report/bfssh";

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

        HttpEntity<ScanResult> entity = new HttpEntity<>(scanResult, headers);
        try {
            restTemplate.postForObject(externalServiceUrl, entity, Void.class);
        } catch (ResourceAccessException e) {
            logger.error("Resource access error while posting scan result: {}", e.getMessage());
            scanStatus.put(scanId, "ERROR: Resource access error while posting scan result");
        } catch (HttpServerErrorException e) {
            logger.error("Server error while posting scan result: {}", e.getMessage());
            scanStatus.put(scanId, "ERROR: Server error while posting scan result");
        } catch (HttpClientErrorException.NotFound e) {
            logger.error("Not Found error while posting scan result: {}", e.getMessage());
            scanStatus.put(scanId, "ERROR: Not Found error while posting scan result");
        }
    }

    /**
     * Lance un scan de ports pour une adresse IP donnée
     *
     * @param scanId Identifiant du scan
     * @return Identifiant du scan
     */
    public String getScanStatus(String scanId) {
        return scanStatus.getOrDefault(scanId, "UNKNOWN_SCAN_ID");
    }
}
