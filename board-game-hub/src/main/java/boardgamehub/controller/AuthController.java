
package boardgamehub.controller;

import boardgamehub.dto.RegisterRequest;
import boardgamehub.dto.LoginRequest;
import boardgamehub.entity.User;
import boardgamehub.service.AuthService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/auth")
public class AuthController {

    private final AuthService authService;

    public AuthController(AuthService authService) {
        this.authService = authService;
    }

    // Registration API
    @PostMapping("/register")
    public ResponseEntity<String> register(
            @Valid @RequestBody RegisterRequest request) {

        User user = new User();
        user.setName(request.getName());
        user.setEmail(request.getEmail());
        user.setPassword(request.getPassword());

        authService.register(user);

        return ResponseEntity.status(HttpStatus.CREATED)
                .body("Registration successful!");
    }

    // Login API
    @PostMapping("/login")
    public ResponseEntity<String> login(
            @Valid @RequestBody LoginRequest request,
            HttpServletRequest httpRequest,
            HttpServletResponse httpResponse) {

        try {
            User user = authService.login(
                    request.getEmail(),
                    request.getPassword()
            );

            Authentication authentication =
                    new UsernamePasswordAuthenticationToken(
                            user,
                            null,
                            List.of(new SimpleGrantedAuthority("ROLE_USER"))
                    );

            SecurityContext context =
                    SecurityContextHolder.createEmptyContext();

            context.setAuthentication(authentication);
            SecurityContextHolder.setContext(context);

            HttpSessionSecurityContextRepository repository =
                    new HttpSessionSecurityContextRepository();

            repository.saveContext(context, httpRequest, httpResponse);

            return ResponseEntity.ok("Login successful!");

        } catch (RuntimeException e) {
            SecurityContextHolder.clearContext();

            return ResponseEntity.status(HttpStatus.UNAUTHORIZED)
                    .body("Invalid email or password");
        }
    }

    // Logout API
    @PostMapping("/logout")
    public ResponseEntity<String> logout(
            HttpServletRequest request) {

        var session = request.getSession(false);

        if (session != null) {
            session.invalidate();
        }

        SecurityContextHolder.clearContext();

        return ResponseEntity.ok("Logout successful!");
    }
}
