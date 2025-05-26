

---

## 1. AppConfig Class

### Code
```java
@Configuration
public class AppConfig {

    @Autowired
    private UserRepository userRepository;

    @Bean
    public UserDetailsService userDetailsService() {
        return username -> {
            return (UserDetails) userRepository.findByUsername(username)
                    .orElseThrow(() -> new UsernameNotFoundException("User not found"));
        };
    }

    @Bean
    public BCryptPasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(userDetailsService());
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
        return authenticationConfiguration.getAuthenticationManager();
    }
}
```

### Explanation
The `AppConfig` class is a Spring configuration class that sets up the core components for Spring Security’s authentication mechanism.

- **Annotation**:
  - `@Configuration`: Marks this class as a Spring configuration class, enabling it to define beans managed by the Spring container.

- **Fields**:
  - `private UserRepository userRepository`: A Spring Data JPA repository (injected via `@Autowired`) used to query user data from the database, such as finding a user by username.

- **Beans**:
  1. **userDetailsService**:
     - **Purpose**: Provides a `UserDetailsService` to load user-specific data (username, password, roles) during authentication.
     - **Process**: 
       - Returns a lambda that takes a username as input.
       - Uses `userRepository.findByUsername(username)` to fetch the user from the database.
       - If no user is found, throws `UsernameNotFoundException`.
       - The returned user object is cast to `UserDetails`, which Spring Security uses for authentication.
     - **Role**: Bridges the application’s database with Spring Security by providing user details.

  2. **passwordEncoder**:
     - **Purpose**: Defines a `BCryptPasswordEncoder` for secure password hashing and verification.
     - **Process**:
       - Creates a `BCryptPasswordEncoder` instance, which uses the bcrypt algorithm to hash passwords.
       - Used during user registration to hash passwords and during login to verify them.
     - **Why BCrypt**: It’s secure, includes a salt, and is computationally slow to deter brute-force attacks.
     - **Role**: Ensures passwords are stored securely and verified correctly.

  3. **authenticationProvider**:
     - **Purpose**: Configures a `DaoAuthenticationProvider` to handle username/password authentication.
     - **Process**:
       - Creates a `DaoAuthenticationProvider` instance.
       - Sets the `userDetailsService` and `passwordEncoder` beans for user retrieval and password verification.
       - Authenticates users by loading details via `UserDetailsService` and verifying passwords with `PasswordEncoder`.
     - **Role**: Performs the core authentication logic, checking credentials and returning an authenticated object.

  4. **authenticationManager**:
     - **Purpose**: Provides an `AuthenticationManager` to process authentication requests.
     - **Process**:
       - Uses `AuthenticationConfiguration` to retrieve the `AuthenticationManager` (implemented as `ProviderManager`).
       - The `ProviderManager` delegates to the configured `AuthenticationProvider` (here, `DaoAuthenticationProvider`).
     - **Role**: Acts as the entry point for authentication, used by login endpoints or filters like `JwtAuthenticationFilter`.

---

## 2. SecurityConfig Class

### Code
```java
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    public static final String AUTHENTICATE = "/authenticate";
    public static final String REGISTER = "/register";
    public static final String REFRESH_TOKEN = "/refreshAccessToken";

    private final AuthenticationProvider authenticationProvider;
    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    public SecurityConfig(AuthenticationProvider authenticationProvider, JwtAuthenticationFilter jwtAuthenticationFilter) {
        this.authenticationProvider = authenticationProvider;
        this.jwtAuthenticationFilter = jwtAuthenticationFilter;
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity httpSecurity) throws Exception {
        httpSecurity
                .csrf(csrf -> csrf.disable())
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers(AUTHENTICATE, REGISTER, REFRESH_TOKEN).permitAll()
                        .requestMatchers("/admin/**").hasRole("ADMIN")
                        .anyRequest().authenticated()
                )
                .sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authenticationProvider(authenticationProvider)
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return httpSecurity.build();
    }
}
```

### Explanation
The `SecurityConfig` class configures HTTP security settings, including endpoint access rules, JWT authentication, and session management.

- **Annotations**:
  - `@Configuration`: Marks this as a Spring configuration class.
  - `@EnableWebSecurity`: Enables Spring Security’s web security features.

- **Constants**:
  - `AUTHENTICATE`, `REGISTER`, `REFRESH_TOKEN`: Define endpoint paths for login (`/authenticate`), user registration (`/register`), and token refresh (`/refreshAccessToken`).
  - **Purpose**: Centralizes endpoint paths for easy maintenance.

- **Constructor**:
  - Injects `AuthenticationProvider` (from `AppConfig`) and `JwtAuthenticationFilter` (a custom filter for JWT validation).
  - These dependencies are used to configure authentication and JWT processing.

- **Bean: filterChain**:
  - **Purpose**: Defines the security filter chain using `HttpSecurity` to control access and authentication.
  - **Process**:
    1. **CSRF**:
       - Disables CSRF protection with `.csrf(csrf -> csrf.disable())`.
       - **Why**: CSRF is unnecessary for stateless JWT-based APIs, as tokens provide security.
    2. **Authorization Rules**:
       - `.requestMatchers(AUTHENTICATE, REGISTER, REFRESH_TOKEN).permitAll()`: Allows unauthenticated access to these public endpoints.
       - `.requestMatchers("/admin/**").hasRole("ADMIN")`: Restricts `/admin/**` endpoints to users with the "ADMIN" role.
       - `.anyRequest().authenticated()`: Requires authentication for all other endpoints.
    3. **Session Management**:
       - `.sessionManagement(sess -> sess.sessionCreationPolicy(SessionCreationPolicy.STATELESS))`: Configures a stateless application, relying on JWTs instead of server-side sessions.
    4. **Authentication Provider**:
       - `.authenticationProvider(authenticationProvider)`: Sets the `DaoAuthenticationProvider` for authentication.
    5. **JWT Filter**:
       - `.addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class)`: Adds the custom `JwtAuthenticationFilter` before Spring’s default username/password filter.
       - **Why**: Validates JWTs in requests to authenticate users.
  - **Role**: Enforces access control, ensures stateless operation, and integrates JWT authentication.

---

## 3. WebConfig Class

### Code
```java
@Configuration
public class WebConfig {

    @Bean
    public WebMvcConfigurer corsConfigurer() {
        return new WebMvcConfigurer() {
            @Override
            public void addCorsMappings(CorsRegistry registry) {
                registry.addMapping("/**")
                        .allowedOrigins("http://localhost:5174")
                        .allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")
                        .allowedHeaders("*")
                        .allowCredentials(true);
            }
        };
    }
}
```

### Explanation
The `WebConfig` class configures CORS to allow cross-origin requests from a specific frontend (e.g., a React app).

- **Annotation**:
  - `@Configuration`: Marks this as a Spring configuration class.

- **Bean: corsConfigurer**:
  - **Purpose**: Enables CORS for the backend to accept requests from a frontend running on `http://localhost:5174`.
  - **Process**:
    - `.addMapping("/**")`: Applies CORS to all endpoints.
    - `.allowedOrigins("http://localhost:5174")`: Permits requests from the specified frontend origin.
    - `.allowedMethods("GET", "POST", "PUT", "DELETE", "OPTIONS")`: Allows these HTTP methods.
    - `.allowedHeaders("*")`: Permits all headers.
    - `.allowCredentials(true)`: Allows credentials (e.g., JWT in headers) to be included.
  - **Role**: Ensures the frontend can communicate with the backend without being blocked by the browser’s same-origin policy.

---

## Authentication Process Flow

### Overview
Spring Security’s authentication involves several components working together:
- **AuthenticationManager**: Processes authentication requests (implemented as `ProviderManager`).
- **AuthenticationProvider**: Performs authentication logic (here, `DaoAuthenticationProvider`).
- **UserDetailsService**: Loads user data from the database.
- **UsernamePasswordAuthenticationToken**: Represents the user’s credentials.
- **ApplicationContext**: Wires all components together.

### Step-by-Step Process
1. **Login Request (via AuthServiceImpl)**:
   - A service (e.g., `AuthServiceImpl`) handles login requests to `/authenticate`.
   - Creates a `UsernamePasswordAuthenticationToken` with the provided username and password:
     ```java
     UsernamePasswordAuthenticationToken authRequest = 
         new UsernamePasswordAuthenticationToken(username, password);
     ```
   - Calls `authenticationManager.authenticate(authRequest)`.

2. **AuthenticationManager (ProviderManager)**:
   - The `AuthenticationManager` (from `AppConfig`) is a `ProviderManager` that delegates to the `DaoAuthenticationProvider`.

3. **DaoAuthenticationProvider**:
   - **User Retrieval**:
     - Calls `userDetailsService` to load the user via `userRepository.findByUsername(username)`.
     - If no user is found, throws `UsernameNotFoundException`.
     - Returns a `UserDetails` object with username, encoded password, and roles.
   - **Password Verification**:
     - Uses `BCryptPasswordEncoder` to compare the provided password with the stored hash.
     - Throws `BadCredentialsException` if they don’t match.
   - **Additional Checks**: Verifies account status (e.g., not locked or expired).
   - If successful, creates an authenticated `UsernamePasswordAuthenticationToken`.

4. **Return Authentication**:
   - The `ProviderManager` returns the authenticated token to `AuthServiceImpl`.
   - The service stores it in `SecurityContextHolder`:
     ```java
     SecurityContextHolder.getContext().setAuthentication(authentication);
     ```
   - A JWT is typically generated and returned to the client.

5. **Protected Endpoint Access**:
   - For subsequent requests, the client includes the JWT in the `Authorization` header.
   - The `JwtAuthenticationFilter` validates the JWT, extracts user details, and sets the `Authentication` in the `SecurityContext`.
   - Spring Security enforces access rules (e.g., `/admin/**` requires "ADMIN" role).

6. **Failure Handling**:
   - If authentication fails (e.g., wrong password), an `AuthenticationException` is thrown and handled (e.g., returning a 401 response).

---

## Overall Application Flow
1. **Registration (`/register`)**:
   - User submits details to `/register` (permitted by `SecurityConfig`).
   - The backend saves the user to the database via `UserRepository`, hashing the password with `BCryptPasswordEncoder`.

2. **Login (`/authenticate`)**:
   - User submits credentials to `/authenticate`.
   - `AuthServiceImpl` uses `AuthenticationManager` to authenticate.
   - If successful, a JWT is returned.

3. **Protected Requests**:
   - JWT is included in requests.
   - `JwtAuthenticationFilter` validates the token and authenticates the user.
   - Access rules are enforced (e.g., `/admin/**` for admins only).

4. **Token Refresh (`/refreshAccessToken`)**:
   - If the JWT expires, the client requests a new one using a refresh token.
   - The backend validates the refresh token and issues a new JWT.

5. **CORS**:
   - The frontend (`http://localhost:5174`) communicates with the backend, enabled by `WebConfig`’s CORS settings.

---

## Assumptions
- **User Entity**: The `UserRepository` interacts with a `User` entity implementing `UserDetails`.
- **JwtAuthenticationFilter**: Validates JWTs, extracts user details, and sets the `Authentication` object.
- **Controllers**: Handle `/authenticate`, `/register`, and `/refreshAccessToken` endpoints.

---

## Best Practices
- **Stateless Design**: Using JWTs and `SessionCreationPolicy.STATELESS` ensures scalability.
- **Secure Passwords**: `BCryptPasswordEncoder` provides strong password hashing.
- **Role-Based Access**: Restricting `/admin/**` to "ADMIN" roles enforces authorization.
- **CORS Security**: Limits cross-origin requests to a trusted origin.
- **Error Handling**: Handle exceptions (e.g., `UsernameNotFoundException`) gracefully in `AuthServiceImpl`.


---



---

## 1. JwtAuthenticationFilter Class

### Code
```java
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
    private final JwtService jwtService;
    private final UserDetailsService userDetailsService;

    public JwtAuthenticationFilter(JwtService jwtService, UserDetailsService userDetailsService) {
        this.jwtService = jwtService;
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        final String authHeader = request.getHeader("Authorization");
        final String token;
        final String username;
        if (authHeader == null || !authHeader.startsWith("Bearer ")) {
            filterChain.doFilter(request, response);
            return;
        }
        token = authHeader.substring(7);
        username = jwtService.getUsernameByToken(token);
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = userDetailsService.loadUserByUsername(username);
            if (!jwtService.isTokenExpired(token)) {
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }
        filterChain.doFilter(request, response);
    }
}
```

### Explanation
The `JwtAuthenticationFilter` is a custom Spring Security filter that processes JWTs in HTTP requests to authenticate users.

- **Annotation**:
  - `@Component`: Marks this class as a Spring-managed component, making it available for dependency injection and inclusion in the security filter chain (as configured in `SecurityConfig`).

- **Fields and Constructor**:
  - `private final JwtService jwtService`: Injected service for JWT operations (e.g., extracting username, validating tokens).
  - `private final UserDetailsService userDetailsService`: Injected service to load user details from the database.
  - **Constructor**: Injects `JwtService` and `UserDetailsService` to be used in the filter logic.

- **Method: `doFilterInternal`**:
  - **Purpose**: Processes each HTTP request to check for a valid JWT and authenticate the user.
  - **Process**:
    1. **Extract Authorization Header**:
       - Retrieves the `Authorization` header from the request.
       - Checks if it exists and starts with `"Bearer "`. If not, the filter passes the request to the next filter in the chain (`filterChain.doFilter`) without processing.
    2. **Extract Token**:
       - If the header is valid, extracts the JWT by removing the `"Bearer "` prefix (starts at index 7).
    3. **Extract Username**:
       - Uses `jwtService.getUsernameByToken(token)` to get the username from the JWT.
    4. **Check Authentication**:
       - Verifies that a username was extracted and no authentication exists in `SecurityContextHolder` (to avoid re-authenticating an already authenticated request).
    5. **Load User Details**:
       - Calls `userDetailsService.loadUserByUsername(username)` to fetch the user’s details (e.g., username, roles) from the database.
    6. **Validate Token**:
       - Checks if the token is not expired using `jwtService.isTokenExpired(token)`.
       - If valid, creates a `UsernamePasswordAuthenticationToken` with the user’s details and authorities, and sets it in `SecurityContextHolder` to mark the user as authenticated.
    7. **Proceed**:
       - Passes the request to the next filter in the chain with `filterChain.doFilter(request, response)`.
  - **Role**: Authenticates requests by validating JWTs and setting the authenticated user in the security context, enabling access to protected endpoints.
  - **Why Important**: Ensures that only requests with valid JWTs can access protected resources, maintaining stateless authentication.

- **Future Clarity**:
  - This filter runs for every HTTP request, checking for a JWT in the `Authorization` header.
  - It integrates with `JwtService` for token operations and `UserDetailsService` for user data, connecting the JWT-based authentication to Spring Security’s context.
  - If the token is invalid or expired, the request proceeds unauthenticated, likely resulting in a 401 (Unauthorized) response for protected endpoints.

---

## 2. JwtService Class

### Code
```java
@Component
public class JwtService {

    @Value("${jwt.secret}")
    private String SECRET_KEY;

    private Key getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(SECRET_KEY);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateToken(UserDetails userDetails) {
        try {
            return Jwts.builder()
                    .setSubject(userDetails.getUsername())
                    .setIssuedAt(new Date())
                    .setExpiration(new Date(System.currentTimeMillis() + 1000 * 60))
                    .signWith(getKey(), SignatureAlgorithm.HS256)
                    .compact();
        } catch (io.jsonwebtoken.ExpiredJwtException e) {
            throw new BaseException(MessageType.EXPIRED_TOKEN, "JWT token has expired: " + e.getMessage());
        } catch (io.jsonwebtoken.JwtException e) {
            throw new BaseException(MessageType.INVALID_TOKEN, "Invalid JWT token: " + e.getMessage());
        }
    }

    private Claims extractAllClaims(String token) {
        return Jwts
                .parserBuilder()
                .setSigningKey(getKey())
                .build()
                .parseClaimsJws(token)
                .getBody();
    }

    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
        final Claims claims = extractAllClaims(token);
        return claimsResolver.apply(claims);
    }

    public String getUsernameByToken(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    public boolean isTokenExpired(String token) {
        return new Date().after(extractClaim(token, Claims::getExpiration));
    }
}
```

### Explanation
The `JwtService` class handles JWT creation, validation, and data extraction.

- **Annotation**:
  - `@Component`: Makes this a Spring-managed bean, injectable into other components like `JwtAuthenticationFilter` and `AuthServiceImpl`.

- **Fields**:
  - `@Value("${jwt.secret}") private String SECRET_KEY`: Retrieves the JWT secret key from application properties (e.g., `application.properties` or `application.yml`) for signing and verifying tokens.

- **Methods**:
  1. **getKey**:
     - **Purpose**: Generates a signing key from the base64-encoded `SECRET_KEY`.
     - **Process**: Decodes the secret key and creates an HMAC-SHA key using `Keys.hmacShaKeyFor`.
     - **Role**: Provides the key for signing and verifying JWTs, ensuring token integrity.

  2. **generateToken**:
     - **Purpose**: Creates a JWT for a user.
     - **Process**:
       - Uses `Jwts.builder()` to create a JWT with:
         - Subject: The user’s username (`userDetails.getUsername()`).
         - Issued At: Current timestamp.
         - Expiration: Current time + 1 minute (1000 * 60 milliseconds).
         - Signature: Signed with the secret key using HS256 algorithm.
       - Handles exceptions by throwing `BaseException` for expired or invalid tokens.
     - **Role**: Generates tokens during login or token refresh, used for authentication.

  3. **extractAllClaims**:
     - **Purpose**: Parses a JWT to extract its claims (payload data).
     - **Process**: Uses `Jwts.parserBuilder()` with the signing key to validate and extract the token’s claims.
     - **Role**: Provides access to token data like username and expiration.

  4. **extractClaim**:
     - **Purpose**: Extracts a specific claim (e.g., username) from the token using a provided function.
     - **Process**: Calls `extractAllClaims` and applies the `claimsResolver` function to get the desired claim.
     - **Role**: Simplifies claim extraction for other methods.

  5. **getUsernameByToken**:
     - **Purpose**: Retrieves the username from a JWT.
     - **Process**: Uses `extractClaim` to get the `subject` claim (username).
     - **Role**: Used by `JwtAuthenticationFilter` to identify the user.

  6. **isTokenExpired**:
     - **Purpose**: Checks if a JWT is expired.
     - **Process**: Compares the current time with the token’s expiration claim.
     - **Role**: Ensures tokens are valid before authenticating users.

- **Future Clarity**:
  - This class is the backbone of JWT operations, handling token creation and validation.
  - The short expiration time (1 minute) is likely for testing; in production, use a longer duration (e.g., 15 minutes) with refresh tokens for longer sessions.
  - The secret key must be securely stored and rotated periodically to maintain security.

---

## 3. AuthServiceImpl Class

### Code
```java
@Service
public class AuthServiceImpl implements IAuthService {
    @Autowired
    private UserRepository userRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;
    @Autowired
    private JwtService jwtService;
    @Autowired
    private AuthenticationManager authenticationManager;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private BCryptPasswordEncoder passwordEncoder;

    @Override
    public AuthReponse registerUser(RegisterRequest registerRequest) {
        if (userRepository.existsByUsername(registerRequest.getUsername())) {
            throw new BaseException(MessageType.NO_RECORD_EXIST, "Bu istifadəçi adı artıq mövcuddur");
        }

        User user = User.builder().username(registerRequest.getUsername()).email(registerRequest.getEmail()).password(passwordEncoder.encode(registerRequest.getPassword())).role("USER").build();

        User dbUser = userRepository.save(user);

        RefreshToken refreshToken = refreshTokenService.createRefreshToken(dbUser);
        String accessToken = jwtService.generateToken(dbUser);

        refreshTokenRepository.save(refreshToken);

        return new AuthReponse(accessToken, refreshToken.getToken());
    }

    @Override
    public AuthReponse authenticate(AuthRequest authRequest) {
        try {
            authenticationManager.authenticate(new UsernamePasswordAuthenticationToken(authRequest.getUsername(), authRequest.getPassword()));
        } catch (BadCredentialsException e) {
            throw new BaseException(MessageType.GENERAL_EXCEPTION, "Yanlış istifadəçi adı və ya şifrə");
        }
        Optional<User> optionalUser = userRepository.findByUsername(authRequest.getUsername());
        if (optionalUser.isEmpty()) {
            throw new BaseException(MessageType.NO_RECORD_EXIST);
        }

        String accessToken = jwtService.generateToken(optionalUser.get());
        RefreshToken refreshToken = refreshTokenService.createRefreshToken(optionalUser.get());

        refreshTokenRepository.save(refreshToken);

        return new AuthReponse(accessToken, refreshToken.getToken());
    }

    @Override
    public AuthReponse refreshAccessToken(String tokenStr) {
        RefreshToken refreshToken = refreshTokenService.validateRefreshToken(tokenStr);
        User user = refreshToken.getUser();
        String newAccessToken = jwtService.generateToken(user);

        return new AuthReponse(newAccessToken, refreshToken.getToken());
    }
}
```

### Explanation
The `AuthServiceImpl` class implements the `IAuthService` interface to handle user registration, authentication, and token refresh.

- **Annotation**:
  - `@Service`: Marks this as a Spring service bean, handling business logic for authentication.

- **Fields**:
  - Injected dependencies include `UserRepository`, `RefreshTokenService`, `JwtService`, `AuthenticationManager`, `RefreshTokenRepository`, and `BCryptPasswordEncoder`.

- **Methods**:
  1. **registerUser**:
     - **Purpose**: Registers a new user and generates access and refresh tokens.
     - **Process**:
       - Checks if the username exists using `userRepository.existsByUsername`. If it does, throws a `BaseException`.
       - Creates a `User` entity with the provided username, email, hashed password (via `passwordEncoder`), and default role "USER".
       - Saves the user to the database.
       - Generates a refresh token using `refreshTokenService.createRefreshToken`.
       - Generates an access token using `jwtService.generateToken`.
       - Saves the refresh token to the database.
       - Returns an `AuthReponse` with both tokens.
     - **Role**: Handles user registration and provides tokens for authentication.

  2. **authenticate**:
     - **Purpose**: Authenticates a user and issues tokens.
     - **Process**:
       - Creates a `UsernamePasswordAuthenticationToken` with the provided credentials.
       - Calls `authenticationManager.authenticate` to verify credentials, catching `BadCredentialsException` for invalid credentials.
       - Retrieves the user from `userRepository.findByUsername`, throwing a `BaseException` if not found.
       - Generates access and refresh tokens, saves the refresh token, and returns an `AuthReponse`.
     - **Role**: Verifies user credentials and provides tokens for secure access.

  3. **refreshAccessToken**:
     - **Purpose**: Generates a new access token using a valid refresh token.
     - **Process**:
       - Validates the refresh token using `refreshTokenService.validateRefreshToken`.
       - Retrieves the associated user from the refresh token.
       - Generates a new access token with `jwtService.generateToken`.
       - Returns an `AuthReponse` with the new access token and the same refresh token.
     - **Role**: Extends user sessions by issuing new access tokens without requiring re-authentication.

- **Future Clarity**:
  - This service handles the core authentication logic, integrating with Spring Security (`AuthenticationManager`) and JWTs (`JwtService`).
  - It ensures secure password storage (`BCryptPasswordEncoder`) and manages refresh tokens for session continuity.
  - The error handling with `BaseException` provides consistent error responses, but the `NO_RECORD_EXIST` message in `registerUser` is misleading (it should indicate "username already exists").

---

## 4. RefreshTokenService Class

### Code
```java
@Service
public class RefreshTokenService implements IRefreshTokenService {

    @Autowired
    private RefreshTokenRepository refreshTokenRepository;

    @Override
    public RefreshToken createRefreshToken(User user) {
        RefreshToken refreshToken = new RefreshToken();
        refreshToken.setToken(UUID.randomUUID().toString());
        refreshToken.setCreatedAt(new Date());
        refreshToken.setExpiredAt(new Date(System.currentTimeMillis() + 1000 * 60 * 60 * 2));
        refreshToken.setRevoked(false);
        refreshToken.setUser(user);

        return refreshToken;
    }

    @Override
    public RefreshToken validateRefreshToken(String tokenStr) {
        RefreshToken token = refreshTokenRepository.findByToken(tokenStr).orElseThrow(() -> new RuntimeException("RefreshToken not found!"));

        if (token.getExpiredAt().before(new Date())) {
            throw new BaseException(MessageType.EXPIRED_TOKEN, "Refresh token müddəti bitib");
        }
        if (token.isRevoked()) {
            token.setRevoked(true);
            refreshTokenRepository.save(token);
            throw new BaseException(MessageType.INVALID_TOKEN, "Refresh token ləğv edilib");
        }

        return token;
    }
}
```

### Explanation
The `RefreshTokenService` manages refresh tokens for extending user sessions.

- **Annotation**:
  - `@Service`: Marks this as a Spring service bean.

- **Fields**:
  - `private RefreshTokenRepository refreshTokenRepository`: Injected repository for database operations on refresh tokens.

- **Methods**:
  1. **createRefreshToken**:
     - **Purpose**: Creates a new refresh token for a user.
     - **Process**:
       - Creates a `RefreshToken` object with:
         - A random UUID as the token.
         - Current timestamp for `createdAt`.
         - Expiration time set to 2 hours from now.
         - `revoked` set to `false`.
         - Associated user.
       - Returns the refresh token (saved later by the caller).
     - **Role**: Generates refresh tokens during registration and authentication.

  2. **validateRefreshToken**:
     - **Purpose**: Validates a refresh token.
     - **Process**:
       - Retrieves the token from `refreshTokenRepository.findByToken`, throwing an exception if not found.
       - Checks if the token is expired by comparing `expiredAt` with the current time, throwing a `BaseException` if expired.
       - Checks if the token is revoked, marking it as revoked and throwing a `BaseException` if true.
       - Returns the valid token.
     - **Role**: Ensures refresh tokens are valid before issuing new access tokens.

- **Future Clarity**:
  - Refresh tokens allow users to stay logged in without re-entering credentials.
  - The 2-hour expiration is reasonable, but consider longer durations (e.g., 7 days) in production.
  - Revoking tokens enhances security by preventing reuse of compromised tokens.

---

## 5. ErrorResponse Class

### Code
```java
@Data
@AllArgsConstructor
@NoArgsConstructor
public class ErrorResponse {
    private int status;
    private String message;
    private String details;
    private LocalDateTime timestamp;

    public ErrorResponse(String message, String details, int status) {
        this.message = message;
        this.details = details;
        this.status = status;
        this.timestamp = LocalDateTime.now();
    }

    public ErrorResponse(MessageType messageType, String details, int status) {
        this(messageType.getMessage(), details, status);
    }
}
```

### Explanation
The `ErrorResponse` class defines a standard structure for error responses.

- **Annotations**:
  - `@Data`: Lombok annotation for getters, setters, and other boilerplate methods.
  - `@AllArgsConstructor`, `@NoArgsConstructor`: Lombok annotations for constructors.

- **Fields**:
  - `status`: HTTP status code (e.g., 401, 404).
  - `message`: Error message (e.g., from `MessageType`).
  - `details`: Additional error details.
  - `timestamp`: Time of the error.

- **Constructors**:
  - Default and all-args constructors (via Lombok).
  - Custom constructor for `message`, `details`, and `status`, setting `timestamp` to the current time.
  - Constructor for `MessageType`, `details`, and `status`, delegating to the custom constructor.

- **Role**: Provides a consistent format for error responses, used by `GlobalExceptionHandler` to return errors to clients.

- **Future Clarity**:
  - This class ensures all errors have a uniform structure, making it easier for clients to parse responses.
  - The `timestamp` field helps track when errors occurred, useful for debugging.

---

## 6. BaseException Class

### Code
```java
@Getter
public class BaseException extends RuntimeException {

    private final String message;
    private final String details;

    public BaseException(MessageType messageType, String details) {
        super(messageType.getMessage());
        this.message = messageType.getMessage();
        this.details = details;
    }

    public BaseException(MessageType messageType) {
        this.message = messageType.getMessage();
        this.details = null;
    }
}
```

### Explanation
The `BaseException` class is a custom exception for application-specific errors.

- **Annotation**:
  - `@Getter`: Lombok annotation for generating getters.

- **Fields**:
  - `message`: The error message (from `MessageType`).
  - `details`: Additional context about the error.

- **Constructors**:
  - `BaseException(MessageType, String)`: Sets the message from `MessageType` and includes details.
  - `BaseException(MessageType)`: Sets the message without details.

- **Role**: Standardizes exception handling, used across the application to throw errors with consistent messages and details.

- **Future Clarity**:
  - This class simplifies error handling by using `MessageType` for predefined error messages.
  - It’s caught by `GlobalExceptionHandler` to return structured `ErrorResponse` objects.

---

## 7. GlobalExceptionHandler Class

### Code
```java
@ControllerAdvice
public class GlobalExceptionHandler {

    @ExceptionHandler(BaseException.class)
    public ResponseEntity<ErrorResponse> handleBaseException(BaseException ex, WebRequest request) {
        ErrorResponse error = new ErrorResponse(
                ex.getMessage(),
                ex.getDetails(),
                determineHttpStatus(ex.getMessage()).value()
        );
        return new ResponseEntity<>(error, determineHttpStatus(ex.getMessage()));
    }

    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwtException(JwtException ex, WebRequest request) {
        ErrorResponse error = new ErrorResponse(
                MessageType.INVALID_TOKEN,
                ex.getMessage(),
                HttpStatus.UNAUTHORIZED.value()
        );
        return new ResponseEntity<>(error, HttpStatus.UNAUTHORIZED);
    }

    @ExceptionHandler(UsernameNotFoundException.class)
    public ResponseEntity<ErrorResponse> handleUsernameNotFoundException(UsernameNotFoundException ex, WebRequest request) {
        ErrorResponse error = new ErrorResponse(
                MessageType.NO_RECORD_EXIST,
                ex.getMessage(),
                HttpStatus.NOT_FOUND.value()
        );
        return new ResponseEntity<>(error, HttpStatus.NOT_FOUND);
    }

    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleMethodArgumentNotValidException(MethodArgumentNotValidException ex, WebRequest request) {
        String details = ex.getBindingResult().getAllErrors().stream()
                .map(error -> {
                    if (error instanceof FieldError) {
                        FieldError fieldError = (FieldError) error;
                        return fieldError.getField() + ": " + fieldError.getDefaultMessage();
                    }
                    return error.getDefaultMessage();
                })
                .collect(Collectors.joining("; "));
        ErrorResponse error = new ErrorResponse(
                MessageType.VALIDATION_ERROR,
                details,
                HttpStatus.BAD_REQUEST.value()
        );
        return new ResponseEntity<>(error, HttpStatus.BAD_REQUEST);
    }

    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleGlobalException(Exception ex, WebRequest request) {
        ErrorResponse error = new ErrorResponse(
                MessageType.GENERAL_EXCEPTION,
                ex.getMessage(),
                HttpStatus.INTERNAL_SERVER_ERROR.value()
        );
        return new ResponseEntity<>(error, HttpStatus.INTERNAL_SERVER_ERROR);
    }

    private HttpStatus determineHttpStatus(String message) {
        if (message.equals(MessageType.NO_RECORD_EXIST.getMessage())) {
            return HttpStatus.NOT_FOUND;
        } else if (message.equals(MessageType.EXPIRED_TOKEN.getMessage()) || message.equals(MessageType.INVALID_TOKEN.getMessage())) {
            return HttpStatus.UNAUTHORIZED;
        } else {
            return HttpStatus.INTERNAL_SERVER_ERROR;
        }
    }
}
```

### Explanation
The `GlobalExceptionHandler` class handles exceptions globally, returning consistent `ErrorResponse` objects.

- **Annotation**:
  - `@ControllerAdvice`: Makes this a global exception handler for all controllers.

- **Methods**:
  1. **handleBaseException**:
     - Handles `BaseException`, returning an `ErrorResponse` with the exception’s message, details, and an HTTP status determined by `determineHttpStatus`.
  2. **handleJwtException**:
     - Handles JWT-related exceptions, returning an `ErrorResponse` with `INVALID_TOKEN` and 401 status.
  3. **handleUsernameNotFoundException**:
     - Handles `UsernameNotFoundException`, returning an `ErrorResponse` with `NO_RECORD_EXIST` and 404 status.
  4. **handleMethodArgumentNotValidException**:
     - Handles validation errors (e.g., invalid DTO fields), aggregating error messages into details and returning an `ErrorResponse` with 400 status.
  5. **handleGlobalException**:
     - Catches all unhandled exceptions, returning an `ErrorResponse` with `GENERAL_EXCEPTION` and 500 status.
  6. **determineHttpStatus**:
     - Maps error messages to HTTP statuses (404 for `NO_RECORD_EXIST`, 401 for `EXPIRED_TOKEN` or `INVALID_TOKEN`, 500 otherwise).

- **Role**: Ensures all exceptions are caught and returned as structured responses, improving client experience.

- **Future Clarity**:
  - This class centralizes error handling, making it easy to add new exception types or modify responses.
  - The `determineHttpStatus` method could be extended to handle more `MessageType` cases.

---

## 8. MessageType Enum

### Code
```java
public enum MessageType {
    NO_RECORD_EXIST("1001", "There is no such thing!"),
    GENERAL_EXCEPTION("1002", "A GENERAL ERROR HAS OCCURRED!"),
    INVALID_TOKEN("1003", "Invalid JWT token"),
    EXPIRED_TOKEN("1004", "Token expired."),
    VALIDATION_ERROR("1005", "Validation Error");

    private final String code;
    private final String message;

    MessageType(String code, String message) {
        this.code = code;
        this.message = message;
    }

    public String getCode() {
        return code;
    }

    public String getMessage() {
        return message;
    }
}
```

### Explanation
The `MessageType` enum defines predefined error codes and messages.

- **Fields**:
  - `code`: A unique error code (e.g., "1001").
  - `message`: A descriptive error message.

- **Values**:
  - `NO_RECORD_EXIST`: For missing records (e.g., user not found).
  - `GENERAL_EXCEPTION`: For generic errors.
  - `INVALID_TOKEN`, `EXPIRED_TOKEN`: For JWT issues.
  - `VALIDATION_ERROR`: For input validation failures.

- **Role**: Provides a centralized way to define error messages, used by `BaseException` and `GlobalExceptionHandler`.

- **Future Clarity**:
  - This enum ensures consistent error messaging across the application.
  - New error types can be added easily by extending the enum.

---

## Overall Process Flow

### 1. User Registration (`/register`)
- **Request**: Client sends a `RegisterRequest` with username, email, and password to `/register` (permitted by `SecurityConfig`).
- **Process**:
  - `AuthServiceImpl.registerUser` checks for duplicate usernames.
  - Creates a `User` with hashed password (`BCryptPasswordEncoder`).
  - Saves the user to the database via `UserRepository`.
  - Generates a refresh token (`RefreshTokenService.createRefreshToken`) and access token (`JwtService.generateToken`).
  - Saves the refresh token and returns an `AuthReponse`.
- **Outcome**: User is registered, and tokens are issued.

### 2. User Login (`/authenticate`)
- **Request**: Client sends an `AuthRequest` with username and password.
- **Process**:
  - `AuthServiceImpl.authenticate` creates a `UsernamePasswordAuthenticationToken` and calls `authenticationManager.authenticate`.
  - The `AuthenticationManager` uses `DaoAuthenticationProvider` to verify credentials via `UserDetailsService` and `BCryptPasswordEncoder`.
  - If successful, retrieves the user, generates tokens, and returns an `AuthReponse`.
- **Outcome**: User is authenticated, and tokens are issued.

### 3. Protected Endpoint Access
- **Request**: Client includes the JWT in the `Authorization` header (e.g., `Bearer <token>`).
- **Process**:
  - `JwtAuthenticationFilter` extracts and validates the JWT using `JwtService`.
  - Loads user details via `UserDetailsService` and sets the `Authentication` in `SecurityContextHolder`.
  - `SecurityConfig` enforces access rules (e.g., `/admin/**` requires "ADMIN" role).
- **Outcome**: Request is allowed or denied based on authentication and authorization.

### 4. Token Refresh (`/refreshAccessToken`)
- **Request**: Client sends a refresh token.
- **Process**:
  - `AuthServiceImpl.refreshAccessToken` validates the refresh token using `RefreshTokenService`.
  - Generates a new access token for the associated user.
  - Returns an `AuthReponse` with the new access token.
- **Outcome**: User session is extended without re-authentication.

### 5. Error Handling
- Exceptions (e.g., `BaseException`, `JwtException`) are caught by `GlobalExceptionHandler`.
- Returns `ErrorResponse` objects with appropriate status codes and messages.

### 6. CORS
- `WebConfig` allows requests from `http://localhost:5174`, enabling frontend-backend communication.

---

## Key Components and Interactions
- **JwtAuthenticationFilter**: Validates JWTs and authenticates requests.
- **JwtService**: Manages JWT creation and validation.
- **AuthServiceImpl**: Handles registration, authentication, and token refresh.
- **RefreshTokenService**: Manages refresh tokens for session continuity.
- **ErrorResponse**, **BaseException**, **GlobalExceptionHandler**, **MessageType**: Ensure consistent error handling and responses.
- **AppConfig** (from previous code): Sets up `UserDetailsService`, `BCryptPasswordEncoder`, `DaoAuthenticationProvider`, and `AuthenticationManager`.
- **SecurityConfig**: Configures HTTP security rules and integrates the JWT filter.
- **WebConfig**: Enables CORS for frontend communication.

---

## Assumptions
- **User Entity**: Implements `UserDetails`, providing username, password, and authorities.
- **RefreshToken Entity**: Stores token, user, creation/expiration dates, and revocation status.
- **Repositories**: `UserRepository` and `RefreshTokenRepository` handle database operations.
- **DTOs**: `RegisterRequest`, `AuthRequest`, and `AuthReponse` are simple data transfer objects.

---

## Best Practices
- **Stateless Authentication**: Uses JWTs and `SessionCreationPolicy.STATELESS` for scalability.
- **Secure Passwords**: `BCryptPasswordEncoder` ensures strong hashing.
- **Error Handling**: `GlobalExceptionHandler` provides consistent error responses.
- **Refresh Tokens**: Securely managed with expiration and revocation checks.
- **CORS**: Restricted to a trusted origin.

