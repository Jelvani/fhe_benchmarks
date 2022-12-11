CXX = g++
RM = rm -rf
SRCS = calculator.cpp main.cpp
INCL = /usr/local/include/SEAL-4.0/
LDLIBS = -lseal-4.0 -ldl

all: calculator

calculator: $(SRCS)
	$(CXX) -pg -g -gdwarf-3 -std=c++17 -o ../../bin/calculator $(SRCS) $(LDLIBS) -I$(INCL)

clean:
	$(RM) calculator test
