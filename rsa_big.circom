pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/bitify.circom";
include "bigint_func.circom";
include "bigint.circom";
// include "circomlib/poseidon.circom";
// include "circomlib/bitify.circom";




template Mod(n, ka, kb) {
    //a mod b
    signal input a[ka];
    signal input b[kb];
    signal output out[kb];

    signal q[ka - kb + 1];
    
    var x[2][100] = long_div(n, kb, ka - kb, a, b);
    for (var i = 0; i < ka - kb + 1; i++) {
        q[i] <-- x[0][i];
    }
    for (var i = 0; i < kb; i++) {
        out[i] <-- x[1][i];
    }

    component mult = BigMult(n, ka - kb + 1, kb);
    for (var i = 0; i < ka - kb + 1; i++) {
        mult.a[i] <== q[i];
    }
    for (var i = 0; i < kb; i++) {
        mult.b[i] <== b[i];
    }
    mult.out[ka] === 0;

    component add = BigAdd(n, ka);
    for (var i = 0; i < ka; i++) {
        add.a[i] <== mult.out[i];
        add.b[i] <== (i < kb) ? out[i] : 0;
    }
    add.out[ka] === 0;
    for (var i = 0; i < ka; i++) {
        add.out[i] === a[i];
    }
}

template Main() {
    signal output out;
}
//a = 87
//b = 23

component main = Mod(2, 4, 3);

/* INPUT = {
    "a": ["3", "1", "1", "1"],
    "b": ["3", "1", "1"]
} */
