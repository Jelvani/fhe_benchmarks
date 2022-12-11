#include "calculator.cpp"
#include <chrono>
using namespace std::chrono;

#define ITER 100
#define POLY_MOD_DEGREE 8192
double get_rand()
{
    return (10000 - 0) * ( (double)rand() / (double)RAND_MAX ) + 0;
}
int main()
{

    Calculator c(POLY_MOD_DEGREE);
    auto start = high_resolution_clock::now();

    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        double ans = c.multiply_cipher(a,b);
    }

    auto stop = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(stop - start);
    cout << "MULTIPLY CIPHER: " << duration.count()/ITER << " milliseconds" << endl;


    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        double ans = c.add_cipher(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "ADD CIPHER: " << duration.count()/ITER << " milliseconds" << endl;

    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        double ans = c.multiply(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "MULTIPLY PLAIN: " << duration.count()/ITER << " milliseconds" << endl;

    start = high_resolution_clock::now();
    for(int i  =0; i < ITER; i++)
    {
        double a = get_rand();
        double b = get_rand();
        double ans = c.add(a,b);
    }

    stop = high_resolution_clock::now();
    duration = duration_cast<milliseconds>(stop - start);
    cout << "ADD PLAIN: " << duration.count()/ITER << " milliseconds" << endl;

    return 1;
}
