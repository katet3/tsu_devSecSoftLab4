# File Encryptor/Decryptor

Консольное приложение для рекурсивного шифрования и дешифрования файлов и папок с использованием AES-256-CBC.

## Полезные ссылки

https://wiki.openssl.org/index.php/EVP_Symmetric_Encryption_and_Decryption

https://stackoverflow.com/questions/918676/generate-sha-hash-in-c-using-openssl-library

https://wiki.openssl.org/index.php/Random_Numbers

https://stackoverflow.com/questions/43192493/aes-256-cbc-encryption-c-using-openssl

https://help.kpda.ru/neutrino/2020/help/index.jsp?topic=%2Fru.kpda.doc.os_ru%2Fhtml%2Flibraries%2Flibc%2Fs%2F_stat.html



## Особенности

- Шифрование/дешифрование одиночных файлов и целых директорий
- Рекурсивная обработка вложенных папок
- Использование криптографического стандарта AES-256
- Реализация паттерна Singleton для менеджера шифрования

## Требования
- Linux-система
- Компилятор C++ с поддержкой C++11
- OpenSSL библиотеки
- Make утилита

## Установка

1. Установите зависимости:

   ```bash
   sudo apt-get update && sudo apt-get install -y g++ libssl-dev make
   ```
2. Клонируйте репозиторий:

   ```bash
   git clone 
   cd file-encryptor
   ```

3. Скомпилируйте проект:

   ```bash
   make
   ```

## Использование

```bash
./file_encryptor <mode> <path> <password>
```

**Параметры:**

- `<mode>`: Режим работы - `encrypt` или `decrypt`
- `<path>`: Путь к файлу или директории
- `<password>`: Пароль для шифрования

**Примеры:**

1. Шифрование директории:

```bash
./file_encryptor encrypt ~/documents MySecretPassword123
```

2. Дешифрование файла:

```bash
./file_encryptor decrypt ~/encrypted/file.dat MySecretPassword123
```

## Особенности реализации

- **Алгоритм шифрования**: AES-256-CBC с 256-битным ключом
- **Генерация ключа**: SHA-256 хеш от пароля
- **Случайный вектор инициализации (IV)**: Генерируется для каждого файла
- **Обработка файлов**: Полная перезапись исходных файлов
- **Логирование**: Вывод статуса операций в консоль