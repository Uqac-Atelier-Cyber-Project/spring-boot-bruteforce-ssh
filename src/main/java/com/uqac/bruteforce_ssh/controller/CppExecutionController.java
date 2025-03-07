package com.uqac.bruteforce_ssh.controller;

import com.uqac.bruteforce_ssh.services.CppExecutionService;
import org.springframework.web.bind.annotation.*;

import java.util.UUID;

@RestController
@RequestMapping("/api")
public class CppExecutionController {
    // Injection de dépendance
    private final CppExecutionService cppExecutionService;

    /**
     * Constructeur
     * @param cppExecutionService
     */
    public CppExecutionController(CppExecutionService cppExecutionService) {
        this.cppExecutionService = cppExecutionService;
    }

    /**
     * Lance un scan de ports en C++ pour une adresse IP donnée
     * @param ip Adresse IP à scanner
     * @param path Chemin du fichier
     * @return Message de confirmation
     */
    @GetMapping("/execute-cpp")
    public String executeCpp(@RequestParam String ip, @RequestParam String path) {
        String scanId = UUID.randomUUID().toString(); // Génère un identifiant unique
        cppExecutionService.executeCppProgram(ip, path, scanId);
        return "Scan lancé avec ID: " + scanId;
    }

    /**
     * Récupère le statut d'un scan à partir de son ID
     * @param scanId ID du scan
     * @return Statut du scan
     */
    @GetMapping("/status/{scanId}")
    public String getScanStatus(@PathVariable String scanId) {
        return cppExecutionService.getScanStatus(scanId);
    }
}
