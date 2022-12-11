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
        double scale = pow(2.0, 40);
        SEALContext* context = NULL;
        KeyGenerator* keygen = NULL;
        SecretKey secret_key;
        PublicKey public_key;
        RelinKeys relin_keys;
        GaloisKeys gal_keys;
        Encryptor* encryptor = NULL;
        Evaluator* evaluator = NULL;
        Decryptor* decryptor = NULL;
        CKKSEncoder* encoder = NULL;
        size_t slot_count;

        Calculator(size_t pmd)
        {
            this->parms = new EncryptionParameters(scheme_type::ckks);
            this->pmd = pmd;
            this->parms->set_poly_modulus_degree(pmd);
            this->parms->set_coeff_modulus(CoeffModulus::Create(pmd, { 60, 40, 40, 60 }));
            this->context = new SEALContext(*parms);
            this->keygen = new KeyGenerator(*context);
            this->secret_key = keygen->secret_key();
            this->keygen->create_public_key(this->public_key);
            this->keygen->create_relin_keys(this->relin_keys);
            this->keygen->create_galois_keys(this->gal_keys);
            this->encryptor = new Encryptor(*(this->context), this->public_key);
            this->evaluator = new Evaluator(*(this->context));
            this->decryptor = new Decryptor(*(this->context), this->secret_key);
            this->encoder = new CKKSEncoder(*(this->context));
            this->slot_count = encoder->slot_count();
            return;
        }

        double multiply_cipher(double a, double b)
        {
            Plaintext p1, p2, presult;
            this->encoder->encode(a,this->scale,p1);
            this->encoder->encode(b,this->scale,p2);
            Ciphertext c1,c2;
            this->encryptor->encrypt(p1,c1);
            this->encryptor->encrypt(p2,c2);
            //result stored in c1
            this->evaluator->multiply_inplace(c1,c2);
            this->decryptor->decrypt(c1,presult);
            vector<double> result;
            this->encoder->decode(presult, result);
            if(fabs(result[0]-a*b) > 1E-4)
            {
                std::ostringstream oss;
                oss.precision(10);
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

        double multiply(double a, double b)
        {
            Plaintext p1, p2, presult;
            this->encoder->encode(a,this->scale,p1);
            this->encoder->encode(b,this->scale,p2);
            Ciphertext c1;
            this->encryptor->encrypt(p1,c1);
            //result stored in c1
            this->evaluator->multiply_plain_inplace(c1,p2);
            this->decryptor->decrypt(c1,presult);
            vector<double> result;
            this->encoder->decode(presult, result);
            if(fabs(result[0]-a*b) > 1E-4)
            {
                std::ostringstream oss;
                oss.precision(20);
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a*b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

        double add_cipher(double a, double b)
        {
            Plaintext p1, p2, presult;
            this->encoder->encode(a,this->scale,p1);
            this->encoder->encode(b,this->scale,p2);
            Ciphertext c1,c2;
            this->encryptor->encrypt(p1,c1);
            this->encryptor->encrypt(p2,c2);
            //result stored in c1
            this->evaluator->add_inplace(c1,c2);
            this->decryptor->decrypt(c1,presult);
            vector<double> result;
            this->encoder->decode(presult, result);
            if(fabs(result[0]-(a+b)) > 1E-4)
            {
                std::ostringstream oss;
                oss.precision(20);
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result[0];

        }

        double add(double a, double b)
        {
            Plaintext p1, p2, presult;
            this->encoder->encode(a,this->scale,p1);
            this->encoder->encode(b,this->scale,p2);
            Ciphertext c1;
            this->encryptor->encrypt(p1,c1);
            //result stored in c1
            this->evaluator->add_plain_inplace(c1,p2);
            this->decryptor->decrypt(c1,presult);
            vector<double> result;
            this->encoder->decode(presult, result);
            if(fabs(result[0]-(a+b)) > 1E-4)
            {
                std::ostringstream oss;
                oss.precision(20);
                oss << "Decrpytion values do not match: " << result[0] << " vs " << a+b;
                throw std::runtime_error(oss.str());
            }
            return result[0];
        }

    private:

};
