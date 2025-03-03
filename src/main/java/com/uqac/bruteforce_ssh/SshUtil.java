package com.uqac.bruteforce_ssh;

import com.jcraft.jsch.JSch;
import com.jcraft.jsch.JSchException;
import com.jcraft.jsch.Session;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

public class SshUtil {

    /**
     * Check if SSH port is open on the given IP
     * @param ip IP address
     * @param port Port number
     * @return True if the port is open, false otherwise
     */
    public static boolean isSshPortOpen(String ip, int port) {
        try {
            Session session = new JSch().getSession("test", ip, port);
            session.setConfig("StrictHostKeyChecking", "no");
            session.connect(3000); // Timeout 3 seconds
            session.disconnect();
            return true;
        } catch (JSchException e) {
            return false;
        }
    }

    /**
     * Try to login to the SSH server with the provided credentials
     * @param ip IP address
     * @param port Port number
     * @param username Username
     * @param password Password
     * @return True if the login is successful, false otherwise
     */
    public static boolean tryLogin(String ip, int port, String username, String password) {
        try {
            JSch jsch = new JSch();
            Session session = jsch.getSession(username, ip, port);
            session.setPassword(password);
            Properties config = new Properties();
            config.put("StrictHostKeyChecking", "no");
            session.setConfig(config);
            session.connect(3000); // Timeout 3 seconds
            session.disconnect();
            return true;
        } catch (JSchException e) {
            return false;
        }
    }

    /**
     * Read credentials from a file
     * @param filePath Path to the file containing credentials
     * @return List of credentials
     * @throws IOException If an I/O error occurs
     */
    public static List<String[]> readCredentialsFromFile(String filePath) throws IOException {
        List<String[]> credentials = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] parts = line.split(":");
                if (parts.length == 2) {
                    credentials.add(parts);
                }
            }
        }
        return credentials;
    }
}