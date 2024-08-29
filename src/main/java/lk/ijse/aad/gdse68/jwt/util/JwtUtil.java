package lk.ijse.aad.gdse68.jwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lk.ijse.aad.gdse68.jwt.dto.UserDto;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.PropertySource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.io.Serializable;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;
//createdd the token using this
@Component
@PropertySource(ignoreResourceNotFound =true,value = "classpath:otherprops.properties")
public class JwtUtil implements Serializable {
    private static final long serialVersionUID=234234523523L;
//    token validation time define
    public static final long JWT_TOKEN_VALIDIT=24*60*60*12;
//    addtionally add the security and get the uniquely token
    @Value("${jwt.secret}")
    private String secretKey;
//    retrieve username from jwt token
public String getUsernameFromToken(String token){
//    extract the token and get the username
    return getClaimFromToken(token, Claims::getSubject);

}
    public Claims getUserRoleCodeFromToken(String token){
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();}

    public Date getExpirationDateFromToken(String token){
//    extract the token and get expire date
    return getClaimFromToken(token,Claims::getExpiration);
    }

    public <T> T getClaimFromToken(String token, Function<Claims, T> claimsResolver){
    final Claims claims=getAllClaimsFromToken(token);
    return claimsResolver.apply(claims);
    }
    private Claims getAllClaimsFromToken(String token){
    return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody();

    }


    private boolean isTokenExpired(String token){
    final Date expiration=getExpirationDateFromToken(token);
    return expiration.before(new Date());
    }
    public String generateToken(UserDto userDTO) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("role", userDTO.getRole());
        return doGenerateToken(claims,userDTO.getEmail());
}
//while creating the token -
    //1. Define claims of the token, like Issuer, Expiration, Subject, and the ID
    //2. Sign the JWT using the HS512 algorithm and secret key.

//    generated the token
    private String doGenerateToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims)
                .setSubject(subject)
                .setIssuedAt(new Date
                        (System.currentTimeMillis()))
                .setExpiration(new Date (System.currentTimeMillis() + JWT_TOKEN_VALIDIT * 1000))
                .signWith(SignatureAlgorithm.HS512,secretKey).compact();
}
//validated the token
    public Boolean validateToken(String token, UserDetails userDetails){
        final String username = getUsernameFromToken(token);
        return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
}

}
