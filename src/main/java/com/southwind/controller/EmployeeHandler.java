package com.southwind.controller;

import com.southwind.entity.employee;
import com.southwind.respository.EmployeeRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

//@CrossOrigin(origins = "http://localhost:8081")
@RestController
@RequestMapping("/employee")
public class EmployeeHandler {
    @Autowired
    private EmployeeRepository employeeRepository;
    @GetMapping("/findall")
    public List<employee> lao(){
        return  employeeRepository.findAll();
    }
}
