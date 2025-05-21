#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <dirent.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

using u8 = unsigned char;

class EncryptionManager {
public:
    /* Паттерн Singleton, получить обьект можно только через статический метод */
    static EncryptionManager& instance() {
        static EncryptionManager manager;
        return manager;
    }

    bool encrypt_file(const std::string& path, const std::string& password) {
        std::ifstream input_file(path, std::ios::binary);
        if (!input_file) {
            std::cerr << "Error opening file for reading: " << path << std::endl;
            return false;
        }
        
        std::vector<u8> plaintext(
            (std::istreambuf_iterator<char>(input_file)),
            std::istreambuf_iterator<char>()
        );
        input_file.close();

        u8 key[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const u8*>(password.data()), 
              password.size(), key);

        u8 initialization_vector[EVP_MAX_IV_LENGTH];
        if (RAND_bytes(initialization_vector, EVP_MAX_IV_LENGTH) != 1) {
            std::cerr << "Error generating initialization vector" << std::endl;
            return false;
        }

        std::vector<u8> ciphertext(plaintext.size() + EVP_MAX_BLOCK_LENGTH);
        const int ciphertext_length = perform_encryption(
            plaintext.data(), 
            plaintext.size(), 
            key, 
            initialization_vector, 
            ciphertext.data()
        );

        if (ciphertext_length < 0) {
            std::cerr << "Encryption process failed" << std::endl;
            return false;
        }
        ciphertext.resize(ciphertext_length);

        std::ofstream output_file(path, std::ios::binary | std::ios::trunc);
        if (!output_file) {
            std::cerr << "Error opening file for writing: " << path << std::endl;
            return false;
        }
        
        output_file.write(
            reinterpret_cast<const char*>(initialization_vector), 
            EVP_MAX_IV_LENGTH
        );
        output_file.write(
            reinterpret_cast<const char*>(ciphertext.data()), 
            ciphertext.size()
        );
        output_file.close();

        return true;
    }

    bool decrypt_file(const std::string& path, const std::string& password) {
        std::ifstream input_file(path, std::ios::binary);
        if (!input_file) {
            std::cerr << "Error opening file for reading: " << path << std::endl;
            return false;
        }

        u8 initialization_vector[EVP_MAX_IV_LENGTH];
        input_file.read(
            reinterpret_cast<char*>(initialization_vector), 
            EVP_MAX_IV_LENGTH
        );
        
        if (input_file.gcount() != EVP_MAX_IV_LENGTH) {
            std::cerr << "Invalid initialization vector size" << std::endl;
            return false;
        }

        std::vector<u8> ciphertext(
            (std::istreambuf_iterator<char>(input_file)),
            std::istreambuf_iterator<char>()
        );
        input_file.close();

        u8 key[SHA256_DIGEST_LENGTH];
        SHA256(reinterpret_cast<const u8*>(password.data()), 
              password.size(), key);

        std::vector<u8> plaintext(ciphertext.size() + EVP_MAX_BLOCK_LENGTH);
        const int plaintext_length = perform_decryption(
            ciphertext.data(), 
            ciphertext.size(), 
            key, 
            initialization_vector, 
            plaintext.data()
        );

        if (plaintext_length < 0) {
            std::cerr << "Decryption process failed. Invalid password?" << std::endl;
            return false;
        }
        plaintext.resize(plaintext_length);

        std::ofstream output_file(path, std::ios::binary | std::ios::trunc);
        if (!output_file) {
            std::cerr << "Error opening file for writing: " << path << std::endl;
            return false;
        }
        
        output_file.write(
            reinterpret_cast<const char*>(plaintext.data()), 
            plaintext.size()
        );
        output_file.close();

        return true;
    }

    void encrypt_directory(const std::string& path, const std::string& password) {
        process_directory(path, password, true);
    }

    void decrypt_directory(const std::string& path, const std::string& password) {
        process_directory(path, password, false);
    }

private:
    /* Паттерн Singleton, получить обьект можно только через статический метод */
    EncryptionManager() = default;
    ~EncryptionManager() = default;
    EncryptionManager(const EncryptionManager&) = delete;
    EncryptionManager& operator=(const EncryptionManager&) = delete;

    int perform_encryption(const u8* plaintext, 
                          int plaintext_length,
                          const u8* key,
                          const u8* initialization_vector,
                          u8* ciphertext) {
        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (!context) return -1;

        if (EVP_EncryptInit_ex(context, EVP_aes_256_cbc(), nullptr, 
                              key, initialization_vector) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }

        int current_length;
        int total_length = 0;

        if (EVP_EncryptUpdate(context, ciphertext, &current_length, 
                             plaintext, plaintext_length) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }
        total_length += current_length;

        if (EVP_EncryptFinal_ex(context, ciphertext + current_length, 
                               &current_length) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }
        total_length += current_length;

        EVP_CIPHER_CTX_free(context);
        return total_length;
    }

    int perform_decryption(const u8* ciphertext,
                          int ciphertext_length,
                          const u8* key,
                          const u8* initialization_vector,
                          u8* plaintext) {
        EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
        if (!context) return -1;

        if (EVP_DecryptInit_ex(context, EVP_aes_256_cbc(), nullptr, 
                              key, initialization_vector) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }

        int current_length;
        int total_length = 0;

        if (EVP_DecryptUpdate(context, plaintext, &current_length, 
                             ciphertext, ciphertext_length) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }
        total_length += current_length;

        if (EVP_DecryptFinal_ex(context, plaintext + current_length, 
                               &current_length) != 1) {
            EVP_CIPHER_CTX_free(context);
            return -1;
        }
        total_length += current_length;

        EVP_CIPHER_CTX_free(context);
        return total_length;
    }

    void process_directory(const std::string& path,
                          const std::string& password,
                          bool encryption_mode) {
        DIR* directory_ptr = opendir(path.c_str());
        if (!directory_ptr) {
            perror("Directory opening error");
            return;
        }

        struct dirent* entry_ptr;
        struct stat status_buffer;

        while ((entry_ptr = readdir(directory_ptr))) {
            const std::string entry_name = entry_ptr->d_name;
            if (entry_name == "." || entry_name == "..") continue;

            const std::string full_path = path + "/" + entry_name;

            if (stat(full_path.c_str(), &status_buffer) == -1) {
                perror("File status error");
                continue;
            }

            if (S_ISDIR(status_buffer.st_mode)) {
                process_directory(full_path, password, encryption_mode);
            } else {
                if (encryption_mode) {
                    if (encrypt_file(full_path, password)) {
                        std::cout << "Successfully encrypted: " << full_path << std::endl;
                    }
                } else {
                    if (decrypt_file(full_path, password)) {
                        std::cout << "Successfully decrypted: " << full_path << std::endl;
                    }
                }
            }
        }

        closedir(directory_ptr);
    }
};

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] 
                 << " <encrypt|decrypt> <target_path> <password>" << std::endl;
        return 1;
    }

    const std::string operation_mode = argv[1];
    const std::string target_path = argv[2];
    const std::string password = argv[3];

    struct stat path_status;
    if (stat(target_path.c_str(), &path_status) != 0) {
        perror("Path status check failed");
        return 1;
    }

    auto& manager = EncryptionManager::instance();

    if (operation_mode == "encrypt") {
        if (S_ISDIR(path_status.st_mode)) {
            manager.encrypt_directory(target_path, password);
        } else {
            manager.encrypt_file(target_path, password);
        }
    } else if (operation_mode == "decrypt") {
        if (S_ISDIR(path_status.st_mode)) {
            manager.decrypt_directory(target_path, password);
        } else {
            manager.decrypt_file(target_path, password);
        }
    } else {
        std::cerr << "Invalid operation mode. Use 'encrypt' or 'decrypt'" << std::endl;
        return 1;
    }

    return 0;
}