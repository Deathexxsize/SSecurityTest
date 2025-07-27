
# Spring Security: Исследование базовой аутентификации
### 1. Настройка проекта и зависимостей
Для начала работы с Spring Security были добавлены следующие основные зависимости в build.gradle:
```
gradle
dependencies {
    implementation 'org.springframework.boot:spring-boot-starter-data-jpa'
    implementation 'org.springframework.boot:spring-boot-starter-security' // Основная зависимость Spring Security
    implementation 'org.springframework.boot:spring-boot-starter-web'
    compileOnly 'org.projectlombok:lombok'
    developmentOnly 'org.springframework.boot:spring-boot-devtools'
    runtimeOnly 'org.postgresql:postgresql'
    annotationProcessor 'org.projectlombok:lombok'
    testImplementation 'org.springframework.boot:spring-boot-starter-test'
    testImplementation 'org.springframework.security:spring-security-test'
    testRuntimeOnly 'org.junit.platform:junit-platform-launcher'
}
```

### 2. Создание тестового контроллера
Был реализован простой REST-контроллер для проверки работы безопасности:

```
@RestController
@RequestMapping
public class HelloController {

    @GetMapping("/")
    public String mainPage() {
        return "Hello, world!";
    }
}
```
### 3. Тестирование механизмов безопасности
#### 3.1. Поведение без Spring Security

При отключенной безопасности (до добавления spring-boot-starter-security):

Доступ к эндпоинту / осуществлялся без аутентификации

В браузере по адресу http://localhost:8080/ отображалось сообщение "Hello, world!"

.

#### 3.2. Поведение с включенной аутентификацией

После добавления Spring Security наблюдались следующие изменения:

При первом обращении к эндпоинту:

Автоматически появилось окно базовой HTTP-аутентификации

Использованы стандартные учетные данные:

Логин: user

Пароль: сгенерирован автоматически (отображается в логах при запуске приложения)

После успешной аутентификации:

Доступ к защищенным ресурсам предоставляется без повторного ввода учетных данных

Состояние аутентификации сохраняется в рамках текущей сессии браузера

.

#### 3.3. Особенности работы сессии
Были проведены следующие тесты для понимания механизма сессий:

Открытие второго окна браузера:

В уже аутентифицированной сессии запросы проходят без повторной аутентификации

Это подтверждает, что состояние аутентификации привязано к сессии браузера

Тестирование в режиме инкогнито:

Требуется повторная аутентификация

Подтверждает изолированность сессий

Тестирование завершения сессии:

При выходе из системы в одном окне браузера

При обновлении страницы в другом окне происходит автоматический выход

Это демонстрирует централизованное управление сессиями Spring Security

.

#### 4. Выводы из первоначального исследования
Spring Security по умолчанию защищает все эндпоинты приложения

Используется базовая HTTP-аутентификация

По умолчанию генерируется пользователь с логином user и случайным паролем

Состояние аутентификации сохраняется в HTTP-сессии

Управление сессиями является централизованным

# Spring Security с кастомным UserDetailsService
Пример настройки Spring Security с базой данных, кастомным UserDetailsService и простейшей формой аутентификации.

### 🧩 Архитектура 
```
+-------------+       +-------------------------+
| HTTP Client | ====> | Spring Security Filters |
+-------------+       +-------------------------+
                              ||
                        (если логин)
                              ||
                   +------------------------+
                   | DaoAuthenticationProvider |
                   +------------------------+
                              ||
               +-------------------------------+
               | MyUserDetailsService          |
               | → UserRepository              |
               | → new UserPrincipal(user)     |
               +-------------------------------+
                              ||
               +-------------------------------+
               | Spring Security проверяет     |
               | пароль, роли, доступ          |
               +-------------------------------+
```
### 💻 Классы и конфигурация

### 🔐 SecurityConfig.java — настройка фильтров и логина java

```
@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Autowired
    private UserDetailsService userDetailsService; // внедряем наш кастомный UserDetailsService

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
                .csrf(csrf -> csrf.disable()) // отключаем CSRF для REST API
                .authorizeHttpRequests(requests ->
                        requests.anyRequest().authenticated() // все запросы требуют авторизации
                )
                .httpBasic(Customizer.withDefaults()) // используем HTTP Basic Auth
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)) // без сессий
                .build();
    }

    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider(); // стандартный провайдер
        provider.setPasswordEncoder(NoOpPasswordEncoder.getInstance()); // без шифрования пароля (для теста!)
        provider.setUserDetailsService(userDetailsService); // используем наш сервис
        return provider;
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration config) throws Exception {
        return config.getAuthenticationManager(); // получаем AuthenticationManager от Spring
    }
}
```
### 👤 UserPrincipal.java — обертка над моделью пользователя

```
public class UserPrincipal implements UserDetails {

    private User user; // обычная модель из БД

    public UserPrincipal(User user) {
        this.user = user;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        // возвращаем роль пользователя, добавляя префикс "ROLE_"
        return List.of(new SimpleGrantedAuthority("ROLE_" + user.getRole()));
    }

    @Override
    public String getPassword() {
        return user.getPassword(); // пароль из базы
    }

    @Override
    public String getUsername() {
        return user.getUsername(); // логин из базы
    }

    // Остальные методы просто говорят, что аккаунт активен
    @Override
    public boolean isAccountNonExpired() { return true; }

    @Override
    public boolean isAccountNonLocked() { return true; }

    @Override
    public boolean isCredentialsNonExpired() { return true; }

    @Override
    public boolean isEnabled() { return true; }
}
```

### 🔍 MyUserDetailsService.java — загрузка пользователя из БД

```
@Service
public class MyUserDetailsService implements UserDetailsService {

    @Autowired
    private UserRepository userRepository; // репозиторий для работы с БД

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        // ищем пользователя по имени
        User user = userRepository.findByUsername(username);

        if (user == null) {
            // если не нашли — кидаем исключение
            throw new UsernameNotFoundException("User not found");
        }

        // возвращаем обёрнутого пользователя
        return new UserPrincipal(user);
    }
}
```
### 🗂️ UserRepository.java — работа с БД через Spring Data

```
@Repository
public interface UserRepository extends JpaRepository<User, Integer> {
    // автоматически сгенерированный метод поиска по username
    User findByUsername(String username);
}
```
### 🔄 Цепочка аутентификации 
Клиент отправляет Authorization: Basic заголовок.

Security вызывает AuthenticationProvider.

Тот — MyUserDetailsService.loadUserByUsername(...).

Пользователь ищется в БД.

Создается UserPrincipal.

Пароль сравнивается.

Если ок — Security впускает в контроллер.

### 📬 Пример запроса
```
GET /user HTTP/1.1
Host: localhost:8080
Authorization: Basic YWRtaW46YWRtaW4=   <-- admin:admin в base64
```
⚠️ Важно
Не используй NoOpPasswordEncoder в боевых проектах! Используй BCryptPasswordEncoder.

Для REST-проектов — отключай csrf и sessions.

Оборачивай свои сущности в UserDetails, чтобы Security мог с ними работать.


.
# 🔐 Spring Security: Регистрация нового пользователя с BCrypt и разрешением публичного эндпоинта
### 🔁 Контроллер UserController — REST-эндпоинт для регистрации
```
@RestController // Говорит Spring, что этот класс — REST-контроллер, возвращающий данные напрямую (JSON)
@RequestMapping // (опционально) базовый путь, не задан — значит просто '/'
public class UserController {

    @Autowired // Внедрение зависимости — Spring подставит бин UserService автоматически
    private UserService userService;

    @PostMapping("/register") // POST-запрос на /register вызывает этот метод
    public User register(@RequestBody User user) {
        return userService.register(user); // Передаём пользователя в сервис
    }
}
```
### 🧠 Сервис UserService — логика регистрации и шифрования пароля
```
@Service // Помечает класс как компонент бизнес-логики, Spring создаёт бин этого класса
public class UserService {

    @Autowired // Внедрение зависимости — Spring подставит реализацию UserRepository
    private UserRepository userRepository;

    // Создаём BCrypt-хешер с уровнем сложности 10 (чем выше — тем медленнее, но безопаснее)
    private final BCryptPasswordEncoder encoder = new BCryptPasswordEncoder(10);

    public User register(User user) {
        // Шифруем пароль перед сохранением — это важно для безопасности!
        user.setPassword(encoder.encode(user.getPassword()));

        // (опционально) Устанавливаем дефолтную роль, если нужно
        // user.setRole(Role.USER);

        // Сохраняем пользователя в базу
        return userRepository.save(user);
    }
}
```
### 🔐 Конфигурация безопасности — разрешаем доступ к /register
```
@Bean
public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    return http
            .csrf(customizer -> customizer.disable()) // Отключаем CSRF (не рекомендуется для HTML-форм, но приемлемо для REST API)
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/register").permitAll()  // 👈 Разрешаем неавторизованным пользователям доступ к /register
                .anyRequest().authenticated() // Все остальные запросы требуют авторизации
            )
            .httpBasic(Customizer.withDefaults()) // Включаем HTTP Basic авторизацию (для тестов через Postman / curl)
            .sessionManagement(session -> 
                session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)   // API не использует сессии, каждый запрос должен быть авторизован заново
            )
            .build(); // Завершаем конфигурацию
}
```
### 📝 Дополнительные пояснения:
requestMatchers("/register").permitAll() — основная строчка, которая открывает доступ к регистрации без логина и пароля. Без неё Spring будет защищать /register, как и все остальные маршруты.

BCryptPasswordEncoder — используется для надёжного хэширования паролей. Нельзя хранить пароли в открытом виде!
