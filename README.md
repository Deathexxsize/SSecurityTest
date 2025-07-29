# 📘 Spring Security + JWT — Документация проекта
### 🧱 Стек:
Spring Boot

Spring Security

JWT (JJWT 0.12.5)

BCrypt

Stateless REST API

### 🔐 Основные задачи:
Разрешить регистрацию и вход без авторизации

Хешировать пароли с помощью BCrypt

Генерировать JWT токен после входа

Валидировать токен через фильтр

Защитить остальные эндпоинты

###📂 Структура компонентов
### ✅ UserController.java — Контроллер регистрации и входа

```
@RestController
@RequestMapping
public class UserController {

    @Autowired
    private UserService userService;

    // Эндпоинт регистрации (разрешён без авторизации)
    @PostMapping("/register")
    public User register(@RequestBody User user) {
        return userService.register(user); // Сохраняет пользователя и хеширует пароль
    }

    // Эндпоинт входа (разрешён без авторизации)
    @PostMapping("/login")
    public String login(@RequestBody User user) {
        return userService.verify(user); // Аутентифицирует и возвращает JWT
    }
}
```
### 🧠 UserService.java — бизнес-логика регистрации и логина

```
@Service
public class UserService {

    @Autowired
    private UserRepository userRepository;

    @Autowired
    private JWTService jwtService;

    @Autowired
    private AuthenticationManager authManager;

    private BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10); // Хешер паролей

    public User register(User user) {
        user.setPassword(encoder.encode(user.getPassword())); // Хешируем пароль перед сохранением
        return userRepository.save(user); // Сохраняем пользователя в базу
    }

    public String verify(User user) {
        Authentication authentication = authManager.authenticate(
                new UsernamePasswordAuthenticationToken(user.getUsername(), user.getPassword())
        );

        if (authentication.isAuthenticated()) {
            return jwtService.generateToken(user.getUsername()); // Выдаём токен при успехе
        } else {
            return "fail";
        }
    }
}
```

### 🔑 JWTService.java — генерация и валидация JWT токена

```
@Service
public class JWTService {

    private String secretkey = "";

    // Генерируем случайный секретный ключ при старте
    public JWTService() {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance("HmacSHA256");
            SecretKey sk = keyGen.generateKey();
            secretkey = Base64.getEncoder().encodeToString(sk.getEncoded());
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    // Генерация JWT токена
    public String generateToken(String username) {
        Map<String, Object> claims = new HashMap<>();

        return Jwts.builder()
                .claims()
                .add(claims)
                .subject(username)
                .issuedAt(new Date(System.currentTimeMillis())) // Время создания
                .expiration(new Date(System.currentTimeMillis() + 60 * 60 * 30)) // Срок действия
                .and()
                .signWith(getKey()) // Подпись токена
                .compact();
    }

    // Получение ключа из строки
    private SecretKey getKey() {
        byte[] keyBytes = Decoders.BASE64.decode(secretkey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    // Извлечение имени пользователя из токена
    public String extractUserName(String token) {
        return extractClaim(token, Claims::getSubject);
    }

    // Универсальный метод извлечения claim
    private <T> T extractClaim(String token, Function<Claims, T> claimResolver) {
        final Claims claims = extractAllClaims(token);
        return claimResolver.apply(claims);
    }

    // Извлечение всех claims
    private Claims extractAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getKey()) // Подтверждаем подпись
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

    // Проверка валидности токена
    public boolean validateToken(String token, UserDetails userDetails) {
        final String userName = extractUserName(token);
        return (userName.equals(userDetails.getUsername()) && !isTokenExpired(token));
    }

    private boolean isTokenExpired(String token) {
        return extractExpiration(token).before(new Date());
    }

    private Date extractExpiration(String token) {
        return extractClaim(token, Claims::getExpiration);
    }
}
```
### 🛡️ SecurityConfig.java — конфигурация Spring Security

```
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private MyUserDetailsService userDetailsService;

    @Autowired
    private JwtFilter jwtFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // Выключаем CSRF
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers("/register", "/login").permitAll() // Открытые маршруты
                        .anyRequest().authenticated()) // Остальное защищено
                .httpBasic(Customizer.withDefaults()) // Basic auth (для отладки)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // Без сессий
                .addFilterBefore(jwtFilter, UsernamePasswordAuthenticationFilter.class) // Наш JWT фильтр
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider () {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setPasswordEncoder(new BCryptPasswordEncoder(12)); // Хешер паролей
        provider.setUserDetailsService(userDetailsService); // Кастомный загрузчик пользователей

        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration configuration) throws Exception {
        return configuration.getAuthenticationManager(); // Менеджер аутентификации
    }
}
```
### 🧼 JwtFilter.java — Фильтр, который перехватывает каждый запрос

```
@Component
public class JwtFilter extends OncePerRequestFilter {

    @Autowired
    private JWTService jwtService;

    @Autowired
    private ApplicationContext context; // Для загрузки MyUserDetailsService

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain)
            throws ServletException, IOException {

        String authHeader = request.getHeader("Authorization");
        String token = null;
        String username = null;

        // Извлекаем JWT из заголовка
        if (authHeader != null && authHeader.startsWith("Bearer ")) {
            token = authHeader.substring(7);
            username = jwtService.extractUserName(token);
        }

        // Если токен валиден, устанавливаем в контекст пользователя
        if (username != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            UserDetails userDetails = context.getBean(MyUserDetailsService.class)
                    .loadUserByUsername(username);

            if (jwtService.validateToken(token, userDetails)) {
                UsernamePasswordAuthenticationToken authToken =
                        new UsernamePasswordAuthenticationToken(
                                userDetails, null, userDetails.getAuthorities());

                authToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(request));
                SecurityContextHolder.getContext().setAuthentication(authToken);
            }
        }

        filterChain.doFilter(request, response); // Продолжаем цепочку фильтров
    }
}
```
### 🧪 Тестирование
```
🔹 Регистрация:
POST /register
{
  "username": "john",
  "password": "123456"
}
```
```
🔹 Логин:
POST /login
{
  "username": "john",
  "password": "123456"
}
```
### 👉 Ответ: строка с JWT-токеном
```
🔹 Защищённые эндпоинты:
При запросе: GET /api/secure-data

Добавь в заголовок:
Authorization: Bearer <token>
```

### ℹ️ Комментарии
Пароли всегда хешируются перед сохранением.

JwtFilter нужен, чтобы проверять токен на каждый запрос, как альтернатива сессии.

Ключ HMAC генерируется каждый раз при перезапуске. В проде — сохраняй ключ или используй application.properties.

Basic auth здесь только для тестов — его можно убрать.
