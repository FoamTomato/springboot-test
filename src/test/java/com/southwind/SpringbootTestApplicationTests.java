package com.southwind;

import com.southwind.respository.EmployeeRepository;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest
class SpringbootTestApplicationTests {
    @Autowired
    EmployeeRepository employeeRepository;

    @Test
    void contextLoads() {
        System.out.println(employeeRepository.findAll());
    }

}
