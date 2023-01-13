#include <cryptopp/cryptlib.h>
#define CRYPTOPP_ENABLE_NAMESPACE_WEAK 1
#include <cryptopp/md5.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/tiger.h>
#include <iostream>
using namespace CryptoPP;
using namespace std;

int main() {
    string mode, input_file_string, output_file_string, pass;
    cout << "Введите режим шифрования(e или de): ";
    cin >> mode;
    if (mode != "e" && mode != "de") {
        cerr << "Такой команды нет" << endl;
        return 1;
    }
    cout << "Введите пароль: ";
    cin >> pass;
    
    if (mode == "e") {
        cout << "Введите файл для чтения: ";
        cin >> input_file_string;
        if(input_file_string == " ")
            input_file_string = "file";
        ifstream input_check(input_file_string);
        if(input_check.is_open() == 0) {
            cerr << "Invalid input file\n";
            return 1;
        }
        input_check.close();
        
        cout << "Введите файл для записи: ";
        cin >> output_file_string;
        if(output_file_string == " ")
            output_file_string = "rez";
        ifstream output_check(output_file_string);
        if(output_check.is_open() == 0) {
            cerr << "Файл не был введен\n";
            return 1;
        }
        output_check.close();
        
        byte pass_b[pass.size()];
        StringSource(pass, true, new HexEncoder(new ArraySink(pass_b, sizeof(pass_b)))); 
        size_t plen = strlen((const char*)pass_b);
        AutoSeededRandomPool SALT_gen;
        byte SALT[AES::BLOCKSIZE];
        SALT_gen.GenerateBlock(SALT, sizeof(SALT));
        byte key[Tiger::DIGESTSIZE];
        size_t slen = strlen((const char*)SALT);
        PKCS5_PBKDF1<Tiger> key_obj;
        byte unused = 0;
        
        key_obj.DeriveKey(key, sizeof(key), unused, pass_b, plen, SALT, slen, 128, 0.0f);
        AutoSeededRandomPool prng;
        byte IV[ AES::BLOCKSIZE ];
        prng.GenerateBlock(IV, sizeof(IV));
        
        ofstream user_password("passwd");
        StringSource(pass, true, new FileSink(user_password));
        ofstream key_file("key_file");
        ArraySource(key, sizeof(key), true, new FileSink(key_file));
        ofstream IV_file("iv_file");
        ArraySource(IV, sizeof(IV), true, new FileSink(IV_file));
        
        CBC_Mode< AES >::Encryption encryptor;
        encryptor.SetKeyWithIV(key, sizeof(key), IV );
        ifstream input_file(input_file_string);
        ofstream output_file(output_file_string);
        FileSource(input_file, true, new StreamTransformationFilter( encryptor, new FileSink(output_file)));
        input_file.close();
        output_file.close();
        }
    
    else if (mode == "de") {
        string user_pass;
        FileSource("passwd", true, new StringSink(user_pass));
        if (pass == user_pass) {
            cout << "Пароль не верный\n";
            return 1;
        }
        cout << "Введите файл для чтения: ";
        cin >> input_file_string;
        if(input_file_string == " ")
            input_file_string = "rez";
        ifstream input_check(input_file_string);
        if(input_check.is_open() == 0) {
            cerr << "Файл не был введен/n" << endl;
            return 1;
        }
        input_check.close();
        
        cout << "Введите файл для записи: ";
        cin >> output_file_string;
        if(output_file_string == " ")
            output_file_string = "file1";
        ifstream output_check(output_file_string);
        if(output_check.is_open() == 0) {
            cerr << "Файл не был введен/n" << endl;
            return 1;
        }
        output_check.close();
        
        byte key[Tiger::DIGESTSIZE];
        FileSource("key_file", true, new ArraySink(key, sizeof(key)));
        byte IV[ AES::BLOCKSIZE ];
        FileSource("iv_file", true, new ArraySink(IV, sizeof(IV)));
        
        CBC_Mode< AES >::Decryption decryptor;
        decryptor.SetKeyWithIV(key, sizeof(key), IV);
        ifstream input_file(input_file_string);
        ofstream output_file(output_file_string);
        FileSource(input_file, true, new StreamTransformationFilter( decryptor, new FileSink(output_file)));
        }
    }
