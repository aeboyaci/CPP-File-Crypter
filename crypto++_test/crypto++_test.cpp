// crypto++_test.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include "cryptlib.h"
#include "rijndael.h"
#include "modes.h"
#include "files.h"
#include "osrng.h"
#include "hex.h"
#include "sha.h"

#include <iostream>
#include <string>
#include <filesystem>

using namespace CryptoPP;
using namespace std;
using namespace std::filesystem;

AutoSeededRandomPool prng;
string myKey = "This can be anything you want! You don't to worry about the length of key.";

SecByteBlock key;
SecByteBlock iv(AES::BLOCKSIZE);

void encryptFile(string fileName)
{
    string outputFileName = fileName + string(".kaiken");

    try
    {
        CBC_Mode< AES >::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv);

        ifstream in(fileName.data(), ios::binary);
        ofstream out(outputFileName, ios::binary);

        FileSource fileSource(in, true, new StreamTransformationFilter(e, new FileSink(out), BlockPaddingSchemeDef::PKCS_PADDING));

        in.close();
        out.close();
        remove(fileName);
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

void decryptFile(string fileName)
{
    string outputFileName = fileName.substr(0, fileName.rfind(string(".kaiken")));

    try
    {
        CBC_Mode< AES >::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv);

        ifstream in(fileName.data(), ios::binary);
        ofstream out(outputFileName, ios::binary);

        FileSource fileSource(in, true, new StreamTransformationFilter(d, new FileSink(out), BlockPaddingSchemeDef::PKCS_PADDING));

        in.close();
        out.close();
    }
    catch (const Exception& e)
    {
        cerr << e.what() << endl;
        exit(1);
    }
}

vector<string> findFiles(string rootPath)
{
    vector<string> paths;

    for (recursive_directory_iterator i(rootPath.data()), end; i != end; ++i)
    {
        if (!is_directory(i->path()))
        {
            paths.push_back(i->path().parent_path().string() + string("\\") + i->path().filename().string());
        }
    }

    return paths;
}

int main(int argc, char* argv[])
{
    SHA256 hash;
    string digest;
    StringSource hashStringSource(myKey, true, new HashFilter(hash, new StringSink(digest)));

    key = SecByteBlock((const CryptoPP::byte*)digest.data(), digest.size());

    prng.GenerateBlock(key, key.size());
    prng.GenerateBlock(iv, iv.size());

    vector<string> paths = findFiles(".\\sample_files");

    for (int i = 0; i < paths.size(); i++)
    {
        // Encryption
        encryptFile(paths.at(i));

        // Decryption
        decryptFile(paths.at(i) + string(".kaiken"));
    }

    return 0;
}