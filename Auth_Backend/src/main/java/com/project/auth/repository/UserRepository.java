package com.project.auth.repository;

import com.project.auth.entity.User;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    Optional<User> findByUsername(String username);


    boolean existsByUsername(@NotBlank(message = "Can't be empty!") @Size(min = 3, max = 10, message = "Min 3 Character, Max 10 Character") String username);
}
