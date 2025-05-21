package com.project.auth.dto;

import jakarta.persistence.Column;
import jakarta.validation.constraints.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class RegisterRequest {

    @NotBlank(message = "Can't be empty!")
    @Size(min = 3, max = 10, message = "Min 3 Character, Max 10 Character")
    @Column(unique = true)
    private String username;

    @NotEmpty
    @Email(message = "Enter valid email address.")
    private String email;


    @NotBlank(message = "Not Blank")
    @NotEmpty(message = "Not empty")
    @Min(value = 8, message = "Min 8 character")
    private String password;



    private String role = "USER";

}
