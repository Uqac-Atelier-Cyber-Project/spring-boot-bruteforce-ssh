package com.uqac.bruteforce_ssh.services;


import com.fasterxml.jackson.databind.ObjectMapper;
import com.uqac.bruteforce_ssh.dto.ScanResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class CppExecutionService {

    /**
     * Logger
     */
    private static final Logger logger = LoggerFactory.getLogger(CppExecutionService.class);

    // Map pour stocker l'état du scan (clé = scanId)
    private final Map<String, String> scanStatus = new ConcurrentHashMap<>();

    /**
     * Exécute le programme C++ de scan de ports
     * @param reportId Identifiant du rapport
     * @param ip Adresse IP à scanner
     * @param path Chemin du fichier
     * @param scanId Identifiant du scan
     */
    @Async
    public void executeCppProgram(Long reportId, String ip, String path, String scanId) {
        try {
            scanStatus.put(scanId, "IN_PROGRESS");

            ProcessBuilder processBuilder = new ProcessBuilder("src/main/resources/cppSSHAttack/sshConnexion", reportId + "", ip, path);
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

                // Désérialisation du JSON vers un objet Java
                ObjectMapper objectMapper = new ObjectMapper();
                ScanResult scanResult = objectMapper.readValue(result.toString(), ScanResult.class);

                // Appel un service externe pour sauvegarder le résultat
                RestTemplate restTemplate = new RestTemplate();
                String externalServiceUrl = "http://localhost:8090/report/bfssh";
                restTemplate.postForObject(externalServiceUrl, scanResult, Void.class);

            } else {
                scanStatus.put(scanId, "ERROR: Exit code " + exitCode + " : " + result.toString());
            }
        } catch (Exception e) {
            scanStatus.put(scanId, "EXCEPTION: " + e.getMessage());
            logger.error("Erreur lors de l'exécution du scan", e);
        }
    }

    /**
     * Lance un scan de ports pour une adresse IP donnée
     * @param scanId Identifiant du scan
     * @return Identifiant du scan
     */
    public String getScanStatus(String scanId) {
        return scanStatus.getOrDefault(scanId, "UNKNOWN_SCAN_ID");
    }
}
