pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";
// include "circomlib/poseidon.circom";
// include "circomlib/bitify.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template Mod(bits) {

    // assumes all inputs are < 2^120
    // returns a mod b

    signal input a;
    signal input b;

    signal output out;
    signal q;
    signal p;
    

    out <-- a % b;
    q <-- a \ b;
    
    p <== q * b;
    a === p + out;

    component bits_out = Num2Bits(bits); // range checks
    component bits_q = Num2Bits(bits);
    bits_out.in <== out;
    bits_q.in <== q;

}



template ModExp (bits) {
    // returns a**b mod c
    signal input a;
    signal input b; //bitsize bits
    signal input c; 
    signal output out;
    
    component n2b = Num2Bits(bits);
    n2b.in <== b;
    
    component mod1[bits];
    component mod2[bits];
    
    signal partial[bits];
    signal doubled[bits];

    signal accum[bits+1];
    accum[bits] <== 1;
    for (var i=bits-1; i>=0; i--) {
        mod1[i] = Mod(bits);
        mod1[i].a <== accum[i+1] * accum[i+1]; //possibly sus, may need to convert to signal
        mod1[i].b <== c;
        doubled[i] <== mod1[i].out;
        partial[i] <== n2b.out[i] * (a-1) + 1;

        mod2[i] = Mod(bits);
        mod2[i].a <== doubled[i] * partial[i];
        mod2[i].b <== c;
        accum[i] <== mod2[i].out;
    }
    out <== accum[0];
}



template GroupVerify (size) {
    // c is list of n, b is list of e, a is signature to encrypt, d is hash
    // encryption is a ** b[i] mod c[i]
    signal input sig;
    signal input e[size];
    signal input n[size];
    signal input message;
    

    component exp[size];
    signal differences[size];
    signal accum[size + 1];
    accum[0] <== 1;

    for (var i = 0; i < size; i++) {
        exp[i] = ModExp(120);
        exp[i].a <== sig;
        exp[i].b <== e[i];
        exp[i].c <== n[i];
        differences[i] <== exp[i].out - message;
        accum[i+1] <== accum[i] * differences[i];
    }
    
    accum[size] === 0;
}


component main {public [e, n, message]} = GroupVerify (5);

/* INPUT = {
    "sig": "3",
    "e": ["77", "10", "1"],
    "n": ["12827", "12827", "12827"],
    "message": "5566"
} */