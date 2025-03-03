package com.uqac.bruteforce_ssh.controller;

import com.uqac.bruteforce_ssh.SshUtil;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;

@RestController
public class SshController {

    /**
     * Check if SSH port is open on the given IP and try to login with the provided credentials
     * @param ip IP address to check
     * @param filePath Path to the file containing credentials
     * @return Result of the check
     */
    @GetMapping("/check-ssh")
    public String checkSsh(@RequestParam String ip, @RequestParam String filePath) {
        int port = 22;

        if (!SshUtil.isSshPortOpen(ip, port)) {
            return "SSH port is not open on " + ip;
        }

        try {
            List<String[]> credentials = SshUtil.readCredentialsFromFile(filePath);
            for (String[] credential : credentials) {
                String username = credential[0];
                String password = credential[1];
                if (SshUtil.tryLogin(ip, port, username, password)) {
                    return "Successful login on " + ip + " with username: " + username + " and password: " + password;
                }
            }
        } catch (IOException e) {
            return "Error reading credentials file: " + e.getMessage();
        }

        return "Failed to login on " + ip + " with provided credentials";
    }
}