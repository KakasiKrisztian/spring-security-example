package com.example.springsecurityexample.student;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class Student {

    private Integer studentId;
    private String studentName;

    public Student(String studentName) {
        this.studentName = studentName;
    }
}
