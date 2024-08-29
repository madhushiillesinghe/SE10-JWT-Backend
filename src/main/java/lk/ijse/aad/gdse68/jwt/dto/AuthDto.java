package lk.ijse.aad.gdse68.jwt.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;

@AllArgsConstructor
@NoArgsConstructor
@Data
@Component
public class AuthDto {
    private String email;
    private String token;
    private  String refreshToken;
}
