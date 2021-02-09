package ru.tveritin.security.model;

import lombok.AllArgsConstructor;
import lombok.Data;

@Data
@AllArgsConstructor
public class Seller {
    private Long id;
    private String firstName;
    private String lastName;
}
