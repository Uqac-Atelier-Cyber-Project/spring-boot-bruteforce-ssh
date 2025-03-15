package com.uqac.bruteforce_ssh.dto;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Getter;
import lombok.Setter;

// Classe pour représenter le résultat du scan
@Getter
@Setter
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ScanResult {
    private Long reportId;
    private String host; // ip address
    private String message;
    private String error;
    private String user; //username
    private String password;

}