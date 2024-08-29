package lk.ijse.aad.gdse68.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Data
public class UserDto {
    private UUID uid;
    private String email;
    private String password;
    private String name;
    private String companyName;
    private String role;
}
