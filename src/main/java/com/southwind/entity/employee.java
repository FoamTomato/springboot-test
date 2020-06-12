package com.southwind.entity;

import lombok.Data;

import javax.persistence.Entity;
import javax.persistence.Id;

@Entity
@Data
public class employee {
    @Id
    private Integer id;
    private String lastName;
    private  String email;
    private  String gender;
}
