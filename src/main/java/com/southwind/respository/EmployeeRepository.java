package com.southwind.respository;

import com.southwind.entity.employee;
import org.springframework.data.jpa.repository.JpaRepository;

public interface EmployeeRepository extends JpaRepository<employee,Integer> {

}
