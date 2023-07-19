## Spring Security Quickguide

* Turn off security: `@SpringBootApplication(exclude = SecurityAutoConfiguration.class)`
* Build project with **Spring security** dependency
* [Dan Vega's amazing intro to Spring Security](https://www.danvega.dev/docs/spring-boot-2-docs/#_spring_security)

### Data model
1) Create entity for storing users, which implements [`UserDetails`](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/apidocs/org/springframework/security/core/userdetails/UserDetails.html)`:
    ```java
    @Entity
    public class User implements UserDetails {
        ...
        private String username;
  
        @Column(length = 100)
        private String password;
  
        private boolean enabled;
  
        @ManyToMany(fetch = FetchType.EAGER, cascade = CascadeType.ALL)
        @JoinTable(
                name = "users_roles",
                joinColumns = @JoinColumn(name = "user_id"),
                inverseJoinColumns = @JoinColumn(name = "role_id")
        )
        private Set<Role> roles = new HashSet<>();
            
        @Override
        public Collection<? extends GrantedAuthority> getAuthorities() {
            return roles.stream()
                    .map(role -> new SimpleGrantedAuthority(role.getName()))
                    .collect(Collectors.toList());
        }
        ...
    }
    ```
2) Create entity for users' roles:
    ```java
    @Entity
    public class Role {
        @Id @GeneratedValue(strategy = GenerationType.IDENTITY)
        private Long id;
    
        private String name;
    
        @ManyToMany(mappedBy = "roles")
        private List<User> users;
    }
    ```

### Service layer implementation
3) Implement interface [`UserDetailsService`](https://docs.spring.io/spring-security/site/docs/4.2.3.RELEASE/apidocs/org/springframework/security/core/userdetails/UserDetailsService.html),
   which provides `UserDetails`:
    ```java
    @Service
    public class UserDetailServiceImpl implements UserDetailsService {
        private final UserRepository userRepository;
   
        @Autowired
        public UserService(UserRepository userRepository) {
            this.userRepository = userRepository;
        }
    
        @Override
        public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
            Optional<User> user = userRepository.findByUsername(username);
    
            if (user.isEmpty()) {
                throw new UsernameNotFoundException(username);
            }
    
            return user.get();
        }
    }
    ```
### Provide custom web security implementation
4) Provide custom implementation of [`WebSecurityConfigurerAdapter`](https://docs.spring.io/spring-security/site/docs/current/api/org/springframework/security/config/annotation/web/configuration/WebSecurityConfigurerAdapter.html)
    ```java
    @Configuration
    @EnableWebSecurity
    public class SecurityConfiguration extends WebSecurityConfigurerAdapter {
    
        private final UserDetailsService userDetailsService;
   
        @Autowired
        public SecurityConfiguration(UserDetailsService userDetailsService) {
            this.userDetailsService = userDetailsService;
        }
    
        @Bean
        public PasswordEncoder encoder() {
            return new BCryptPasswordEncoder();
        }
    
        @Override
        protected void configure(AuthenticationManagerBuilder auth) throws Exception {
            auth.userDetailsService(userDetailsService);
        }
    
        @Override
        protected void configure(HttpSecurity http) throws Exception {
            http
                    .authorizeRequests()
                    .antMatchers("/posts/**").hasRole("USER")
                    .antMatchers("/**").permitAll()
                    .and()
                    .formLogin()
                    .and()
                    .logout();
        }
    }
    ```

### How to

#### Log in & Log out
Navigate to `/login` and `/logout`.

#### Register new user
Saving new user is simple. Just make sure to handle password properly:

```java
private final UserRepository userRepository;
private final PasswordEncoder passwordEncoder;

public void registerUser(String username, String password) throws UserAlreadyExistException {
    if (userRepository.findByUsername(username).isPresent()) {
        throw new UserAlreadyExistException(String.format("User %s already exists", username));
    }

    Role role = new Role();
    role.setName("ROLE_USER");

    User user = new User();
    user.setUsername(username);
    user.setEnabled(true);
    user.addRole(role);
    user.setPassword(passwordEncoder.encode(password));

    userRepository.save(user);
}
```

## JWT Quickguide
1) Create Util Class

```java
    import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Component
public class JwtUtil {


    private static final String SECRET_KEY = "1lfVinP+BuZ8xPt3/r7PsUXmXiSxtqhX7KCpS+/teoA=";

    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .setSigningKey(SECRET_KEY)
                .parseClaimsJws(token)
                .getBody();
    }

    private Boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    public String generateToken(UserDetails userDetails) {
        Map<String, Object> claims = new HashMap<>();
        return createToken(claims, userDetails.getUsername());
    }

    private String createToken(Map<String, Object> claims, String subject) {
        return Jwts.builder()
                .setClaims(claims) // payload right here
                .setSubject(subject) // should be unique string like username or email
                .setIssuedAt(new Date(System.currentTimeMillis()))
                .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 10)) / 10 hours from now
                .signWith(SignatureAlgorithm.HS256, SECRET_KEY) // sign with the secret key 
                .compact();
    }

    public Boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUsername(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }
}
```
2) Create AuthenticationRequest & AuthenticationResponse
```java
public class AuthenticationRequest {

    private String username;
    private String password;

    //need default constructor for JSON Parsing
    public AuthenticationRequest() {

    }

    public AuthenticationRequest(String username, String password) {
        this.setUsername(username);
        this.setPassword(password);
    }

    public String getUsername() {
        return username;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public String getPassword() {
        return password;
    }

    public void setPassword(String password) {
        this.password = password;
    }

}
```
```java
public class AuthenticationResponse {

    private final String jwt;

    public AuthenticationResponse(String jwt) {
        this.jwt = jwt;
    }

    public String getJwt() {
        return jwt;
    }
}
```


