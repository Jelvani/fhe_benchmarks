#include "openfhe.h"
#include <vector>
#include <cmath>
#include <chrono>
using namespace std::chrono;

#define ITER 200
#define DEPTH 2
#define PMD 65537
using namespace lbcrypto;
using namespace std;

class Calculator
{
    public:
        CCParams<CryptoContextBFVRNS>* parms = NULL;
        size_t pmd;
        CryptoContext<DCRTPoly> context;
        KeyPair<DCRTPoly> keyPair;

        Calculator(size_t pmd, int depth)
        {
            this->parms = new CCParams<CryptoContextBFVRNS>();
            this->pmd = pmd;
            this->parms->SetPlaintextModulus(this->pmd);
            this->parms->SetMultiplicativeDepth(depth);
            this->context = GenCryptoContext(*(this->parms));
            this->context->Enable(PKE);
            this->context->Enable(KEYSWITCH);
            this->context->Enable(LEVELEDSHE);
            this->keyPair = this->context->KeyGen();
            this->context->EvalMultKeyGen(keyPair.secretKey);
            return;
        }

        int multiply_cipher(int a, int b)
        {
            std::vector<int64_t> vectorOfInts1 = {a};
            std::vector<int64_t> vectorOfInts2 = {b};

            Plaintext p1, p2, presult;
            p1 = this->context->MakePackedPlaintext(vectorOfInts1);
            p2 = this->context->MakePackedPlaintext(vectorOfInts2);


            auto c1 = this->context->Encrypt(this->keyPair.publicKey,p1);
            auto c2 = this->context->Encrypt(this->keyPair.publicKey,p2);
            auto res = this->context->EvalMult(c1,c2);
            this->context->Decrypt(this->keyPair.secretKey,res,&presult);
            int result =  presult->GetPackedValue()[0];


            if(result != a*b)
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result;
            
            return 0;
        }

        int multiply(int a, int b)
        {
            std::vector<int64_t> vectorOfInts1 = {a};
            std::vector<int64_t> vectorOfInts2 = {b};

            Plaintext p1, p2, presult;
            p1 = this->context->MakePackedPlaintext(vectorOfInts1);
            p2 = this->context->MakePackedPlaintext(vectorOfInts2);


            auto c1 = this->context->Encrypt(this->keyPair.publicKey,p1);
            auto res = this->context->EvalMult(c1,p2);
            this->context->Decrypt(this->keyPair.secretKey,res,&presult);
            int result =  presult->GetPackedValue()[0];


            if(result != a*b)
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result;
            
            return 0;
        }

        int add_cipher(int a, int b)
        {
            std::vector<int64_t> vectorOfInts1 = {a};
            std::vector<int64_t> vectorOfInts2 = {b};

            Plaintext p1, p2, presult;
            p1 = this->context->MakePackedPlaintext(vectorOfInts1);
            p2 = this->context->MakePackedPlaintext(vectorOfInts2);


            auto c1 = this->context->Encrypt(this->keyPair.publicKey,p1);
            auto c2 = this->context->Encrypt(this->keyPair.publicKey,p2);
            auto res = this->context->EvalAdd(c1,c2);
            this->context->Decrypt(this->keyPair.secretKey,res,&presult);
            int result =  presult->GetPackedValue()[0];


            if(result != a+b)
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result;
            
            return 0;
        }

        int add(int a, int b)
        {
            std::vector<int64_t> vectorOfInts1 = {a};
            std::vector<int64_t> vectorOfInts2 = {b};

            Plaintext p1, p2, presult;
            p1 = this->context->MakePackedPlaintext(vectorOfInts1);
            p2 = this->context->MakePackedPlaintext(vectorOfInts2);


            auto c1 = this->context->Encrypt(this->keyPair.publicKey,p1);
            auto c2 = this->context->Encrypt(this->keyPair.publicKey,p2);
            auto res = this->context->EvalAdd(c1,p2);
            this->context->Decrypt(this->keyPair.secretKey,res,&presult);
            int result =  presult->GetPackedValue()[0];


            if(result != a+b)
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result;
            
            return 0;
        }


};


int get_rand()
{
    return (10000) * ( (int)rand() / (int)RAND_MAX );
}

int main(){
    Calculator c(PMD,DEPTH);
    auto start = high_resolution_clock::now();

    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        c.multiply_cipher(a,b);
    }

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "MULTIPLY CIPHER: " << duration.count()/ITER << " milliseconds" << endl;


    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        c.add_cipher(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "ADD CIPHER: " << duration.count()/ITER << " milliseconds" << endl;

    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        c.multiply(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "MULTIPLY PLAIN: " << duration.count()/ITER << " milliseconds" << endl;

    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        c.add(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "ADD PLAIN: " << duration.count()/ITER << " milliseconds" << endl;
}