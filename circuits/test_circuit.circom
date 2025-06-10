pragma circom 2.1.6;

include "circuits/poseidon.circom";
// include "https://github.com/0xPARC/circom-secp256k1/blob/master/circuits/bigint.circom";

template NumToBits () {
    signal input x;
    signal output b[4];

    for (var i=0; i<4; i++) {
        b[i] <-- (x&(1<<i)) >> i;
    }

    var accum = 0;
    for (var i=0; i<4; i++) {
        accum += (2 ** i) * b[i];
    }
    accum === x;
    for (var i=0; i<4; i++) {
        b[i] * (b[i] - 1) === 0;
    }
}

template Main () {
    signal input in;
    signal output out; // twice the third bit of in

    component n2b = NumToBits();
    n2b.x <== in;
    
    out <-- n2b.b[3] * 2;
    out === n2b.b[3] * 2;
}

component main = Main();

/* INPUT = {
    "in": "11"
} */