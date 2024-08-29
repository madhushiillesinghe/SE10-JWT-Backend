package lk.ijse.aad.gdse68.jwt.service;

import lk.ijse.aad.gdse68.jwt.dto.UserDto;

public interface UserService {
    int saveUser(UserDto userDto);
    UserDto searchUser(String userName);
}
