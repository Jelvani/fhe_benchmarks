#include <seal/seal.h>
#include <vector>
#include <cmath>

using namespace std;
using namespace seal;

class Calculator
{
    public:
        EncryptionParameters* parms = NULL;
        size_t pmd;
        SEALContext* context = NULL;
        KeyGenerator* keygen = NULL;
        SecretKey secret_key;
        PublicKey public_key;
        RelinKeys relin_keys;
        GaloisKeys gal_keys;
        Encryptor* encryptor = NULL;
        Evaluator* evaluator = NULL;
        Decryptor* decryptor = NULL;
        BatchEncoder* encoder = NULL;
        size_t slot_count;

        Calculator(size_t pmd)
        {
            this->parms = new EncryptionParameters(scheme_type::bfv);
            this->pmd = pmd;
            this->parms->set_poly_modulus_degree(pmd);
            this->parms->set_coeff_modulus(CoeffModulus::BFVDefault(pmd));
            this->parms->set_plain_modulus(PlainModulus::Batching(pmd, 20));
            this->context = new SEALContext(*parms);
            this->keygen = new KeyGenerator(*context);
            this->secret_key = keygen->secret_key();
            
            this->keygen->create_public_key(this->public_key);
            this->keygen->create_relin_keys(this->relin_keys);
            this->keygen->create_galois_keys(this->gal_keys);
            this->encryptor = new Encryptor(*(this->context), this->public_key);
            this->evaluator = new Evaluator(*(this->context));
            this->decryptor = new Decryptor(*(this->context), this->secret_key);
            this->encoder = new BatchEncoder(*(this->context));
            this->slot_count = encoder->slot_count();
            
            return;
        }

        uint64_t multiply_cipher(uint64_t a, uint64_t b)
        {
            Plaintext p1, p2, presult;
            vector<uint64_t> av = {a};
            vector<uint64_t> bv = {b};
            this->encoder->encode(av,p1);
            this->encoder->encode(bv,p2);
            Ciphertext c1,c2;
            this->encryptor->encrypt(p1,c1);
            this->encryptor->encrypt(p2,c2);
            //result stored in c1
            this->evaluator->multiply_inplace(c1,c2);
            this->decryptor->decrypt(c1,presult);
            vector<uint64_t> result;
            this->encoder->decode(presult, result);
            if(result[0]!=(a*b))
            {
                std::ostringstream oss;
                oss.precision(10);
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

        uint64_t multiply(uint64_t a, uint64_t b)
        {
            Plaintext p1, p2, presult;
            vector<uint64_t> av = {a};
            vector<uint64_t> bv = {b};
            this->encoder->encode(av,p1);
            this->encoder->encode(bv,p2);
            Ciphertext c1;
            this->encryptor->encrypt(p1,c1);
            //result stored in c1
            this->evaluator->multiply_plain_inplace(c1,p2);
            this->decryptor->decrypt(c1,presult);
            vector<uint64_t> result;
            this->encoder->decode(presult, result);
            if(result[0]!=(a*b))
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

        uint64_t add_cipher(uint64_t a, uint64_t b)
        {
            Plaintext p1, p2, presult;
            vector<uint64_t> av = {a};
            vector<uint64_t> bv = {b};
            this->encoder->encode(av,p1);
            this->encoder->encode(bv,p2);
            Ciphertext c1,c2;
            this->encryptor->encrypt(p1,c1);
            this->encryptor->encrypt(p2,c2);
            //result stored in c1
            this->evaluator->add_inplace(c1,c2);
            this->decryptor->decrypt(c1,presult);
            vector<uint64_t> result;
            this->encoder->decode(presult, result);
            if(result[0]!=(a+b))
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result[0];

        }

        uint64_t add(uint64_t a, uint64_t b)
        {
            Plaintext p1, p2, presult;
            vector<uint64_t> av = {a};
            vector<uint64_t> bv = {b};
            this->encoder->encode(av,p1);
            this->encoder->encode(bv,p2);
            Ciphertext c1;
            this->encryptor->encrypt(p1,c1);
            //result stored in c1
            this->evaluator->add_plain_inplace(c1,p2);
            this->decryptor->decrypt(c1,presult);
            vector<uint64_t> result;
            this->encoder->decode(presult, result);
            if(result[0]!=(a+b))
            {
                std::ostringstream oss;
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

    private:

};
