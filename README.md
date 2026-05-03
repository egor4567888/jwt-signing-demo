# jwt-signing-demo

Демо-сервис на Spring Security и nimbus-jose-jwt: принимает **вложенный JWE-токен** (зашифрованный JWE, внутри которого подписанный JWS), расшифровывает его своим приватным ключом и проверяет подпись клиента публичным ключом.

## Идея

```
[Клиент] ── создаёт JWS (подписан privateKey клиента)
           │
           └── оборачивает в JWE (зашифрован publicKey сервера)
                                  │
                                  ▼
[Сервер] ── расшифровывает JWE приватным ключом сервера (PKCS12 keystore)
           ── разбирает JWS внутри
           ── проверяет подпись публичным ключом клиента (PEM)
           └── отдаёт payload или 401
```

## Стек

- Java 17, Spring Boot 3.5
- Spring Security (фильтр аутентификации, требование HTTPS на всех эндпоинтах кроме `/api/token`)
- nimbus-jose-jwt 10.4
- HTTPS поверх PKCS12 keystore

## Запуск

### 1. Сгенерировать ключи

```bash
cd src/main/resources

# Серверный keystore (для расшифровки JWE и для HTTPS)
keytool -genkeypair -alias jwtserver \
  -keyalg RSA -keysize 2048 \
  -storetype PKCS12 -keystore keystore.p12 \
  -storepass password -validity 365 \
  -dname "CN=localhost, OU=dev, O=local, L=SPB, ST=SPB, C=RU"

# Клиентская пара ключей (для подписи JWS клиентом)
openssl genrsa -out private.pem 2048
openssl rsa -in private.pem -pubout -out public.pem
```

> `private.pem` хранится у клиента, `public.pem` — у сервера для проверки подписи.

### 2. Запустить сервер

```bash
./gradlew bootRun
```

Сервер слушает HTTPS на `:8443`. Эндпоинт: `POST /api/token` с JWE-строкой в теле.

### 3. Запустить тестового клиента

```bash
./gradlew run -PmainClass=org.example.testClient.TestClient
```

Клиент собирает JWS → оборачивает в JWE → отправляет на сервер.
