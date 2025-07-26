
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
