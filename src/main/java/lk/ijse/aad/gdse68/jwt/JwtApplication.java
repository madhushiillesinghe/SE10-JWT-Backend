package lk.ijse.aad.gdse68.jwt;



import org.modelmapper.ModelMapper;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class JwtApplication {
    public static void main(String[] args) {
        SpringApplication.run(JwtApplication.class, args);
    }
//    using model mapper entity and dto connecting
    @Bean
    public ModelMapper modelMapper(){
        return new ModelMapper();
}
}
