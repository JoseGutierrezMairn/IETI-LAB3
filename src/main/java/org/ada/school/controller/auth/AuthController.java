package org.ada.school.controller.auth;

import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.ada.school.exception.InvalidCredentialsException;
import org.ada.school.repository.document.User;
import org.ada.school.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.web.bind.annotation.*;

import java.util.Calendar;
import java.util.Date;

import static org.ada.school.utils.Constants.*;

@RestController
@RequestMapping( "/v1/auth" )
public class AuthController
{

    @Value( "${app.secret}" )
    String secret;

    @Value( "${app.secret_admin}" )
    String secretAdmin;

    private final UserService userService;

    public AuthController( @Autowired UserService userService )
    {
        this.userService = userService;
    }


    @PostMapping("/adminToken")
    public TokenDto loginAdminRoleToken( @RequestBody SecretAdminDto secretAdmin )
    {
        if ( secretAdmin.getSecretAdmin().equals( this.secretAdmin ) )
        {
            return generateAdminTokenDto();
        }
        else
        {
            throw new InvalidCredentialsException();
        }

    }
    @PostMapping
    public TokenDto login( @RequestBody LoginDto loginDto )
    {
        User user = userService.findByEmail( loginDto.email );
        if ( BCrypt.checkpw( loginDto.password, user.getPasswordHash() ) )
        {
            return generateTokenDto( user );
        }
        else
        {
            throw new InvalidCredentialsException();
        }

    }



    private String generateToken( User user, Date expirationDate )
    {
        return Jwts.builder()
                .setSubject( user.getId() )
                .claim(CLAIMS_ROLES_KEY, user.getRoles() )
                .setIssuedAt(new Date() )
                .setExpiration( expirationDate )
                .signWith( SignatureAlgorithm.HS256, secret )
                .compact();
    }

    private TokenDto generateTokenDto( User user )
    {
        Calendar expirationDate = Calendar.getInstance();
        expirationDate.add( Calendar.MINUTE, TOKEN_DURATION_MINUTES );
        String token = generateToken( user, expirationDate.getTime() );
        return new TokenDto( token, expirationDate.getTime() );
    }

    private TokenDto generateAdminTokenDto()
    {
        Calendar expirationDate = Calendar.getInstance();
        expirationDate.add( Calendar.MINUTE, TOKEN_DURATION_TEN_MINUTES );
        String token =Jwts.builder()
                .setSubject( "admin" )
                .claim(CLAIMS_ROLES_KEY, ADMIN_ROLE )
                .setIssuedAt(new Date() )
                .setExpiration( expirationDate.getTime() )
                .signWith( SignatureAlgorithm.HS256, secretAdmin )
                .compact();
        return new TokenDto( token, expirationDate.getTime() );
    }

}