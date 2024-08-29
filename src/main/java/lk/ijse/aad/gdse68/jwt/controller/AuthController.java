package lk.ijse.aad.gdse68.jwt.controller;



import lk.ijse.aad.gdse68.jwt.dto.AuthDto;
import lk.ijse.aad.gdse68.jwt.dto.ResponseDto;
import lk.ijse.aad.gdse68.jwt.dto.UserDto;
import lk.ijse.aad.gdse68.jwt.service.impl.UserServiceImpl;
import lk.ijse.aad.gdse68.jwt.util.JwtUtil;
import lk.ijse.aad.gdse68.jwt.util.VarList;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.*;


@CrossOrigin
@RestController
@RequestMapping("api/v1/auth")
public class AuthController {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;
    private final UserServiceImpl userService;
    private final ResponseDto responseDTO;

    //constructor injection
    public AuthController(JwtUtil jwtUtil, AuthenticationManager authenticationManager, UserServiceImpl userService,ResponseDto responseDTO) {
        this.jwtUtil = jwtUtil;
        this.authenticationManager = authenticationManager;
        this.userService = userService;
        this.responseDTO = responseDTO;
    }

    @PostMapping("/authenticate")
    public ResponseEntity<ResponseDto> authenticate(@RequestBody UserDto userDTO) {
        try {
            authenticationManager.authenticate(
                    new UsernamePasswordAuthenticationToken(userDTO.getEmail(), userDTO.getPassword()));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body(new ResponseDto(VarList.Unauthorized, "Invalid Credentials", e.getMessage()));
        }

        UserDto loadedUser = userService.loadUserDetailByUsername(userDTO.getEmail());
        if (loadedUser == null) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ResponseDto(VarList.Conflict, "Authorization Failure! Please Try Again", null));
        }

        String token = jwtUtil.generateToken(loadedUser);
        if (token == null || token.isEmpty()) {
            return ResponseEntity.status(HttpStatus.CONFLICT)
                    .body(new ResponseDto(VarList.Conflict, "Authorization Failure! Please Try Again", null));
        }

        AuthDto authDTO = new AuthDto();
        authDTO.setEmail(loadedUser.getEmail());
        authDTO.setToken(token);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body(new ResponseDto(VarList.Created, "Success", authDTO));
    }
    @PostMapping(value = "/register")
    public ResponseEntity<ResponseDto> registerUser(@RequestBody UserDto userDTO) {
        try {
            int res = userService.saveUser(userDTO);
            switch (res) {
                case VarList.Created -> {
                    String token = jwtUtil.generateToken(userDTO);
                    AuthDto authDTO = new AuthDto();
                    authDTO.setEmail(userDTO.getEmail());
                    authDTO.setToken(token);
                    return ResponseEntity.status(HttpStatus.CREATED)
                            .body(new ResponseDto(VarList.Created, "Success", authDTO));
                }
                case VarList.Not_Acceptable -> {
                    return ResponseEntity.status(HttpStatus.NOT_ACCEPTABLE)
                            .body(new ResponseDto(VarList.Not_Acceptable, "Email Already Used", null));
                }
                default -> {
                    return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                            .body(new ResponseDto(VarList.Bad_Gateway, "Error", null));
                }
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(new ResponseDto(VarList.Internal_Server_Error, e.getMessage(), null));
        }
    }
}
