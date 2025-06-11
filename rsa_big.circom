pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
include "node_modules/circomlib/circuits/multiplexer.circom";
include "bigint_func.circom";
include "bigint.circom";
// include "circomlib/poseidon.circom";
// include "circomlib/multiplexer.circom";




template BigMod(n, ka, kb) {
    //a mod b; output length kb
    signal input a[ka];
    signal input b[kb];
    signal output out[kb];

    signal q[ka];
    
    var x[2][100] = long_div_gen(n, ka, kb, a, b);
    for (var i = 0; i < ka; i++) {
        q[i] <-- x[0][i];
    }
    for (var i = 0; i < kb; i++) {
        out[i] <-- x[1][i];
    }

    component mult = BigMult(n, ka, kb);
    for (var i = 0; i < ka; i++) {
        mult.a[i] <== q[i];
    }
    for (var i = 0; i < kb; i++) {
        mult.b[i] <== b[i];
    }
    for (var i = ka; i < ka + kb; i++) {
        mult.out[i] === 0;
    }

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

template BigModExp (n, k, exp_bits) {
    // outputs a**b mod c, where b is expressed AS AN ARRAY OF BITS 
    signal input a[k];
    signal input b[exp_bits];
    signal input c[k];
    signal output out[k];

    component mod1[exp_bits];
    component mod2[exp_bits];
    component mul1[exp_bits];
    component mul2[exp_bits];

    signal partial[exp_bits + 1][k];
    signal powers[exp_bits][k];
    partial[0][0] <== 1;
    for (var i = 0; i < k; i++) {
        powers[0][i] <== a[i];
        if (i > 0) {
            partial[0][i] <== 0;
        }
    }
    // powers[0] <== a;

    for (var i = 0; i < exp_bits; i++) {
        // mod1[i] = BigMod(n, 2*k, k);
        // store the partial products in partial[i+1]
        mul1[i] = BigMult(n, k, k);
        for (var j = 0; j < k; j++) {
            mul1[i].a[j] <== partial[i][j];
            mul1[i].b[j] <== b[i] * (powers[i][j] - ((j == 0) ? 1 : 0)) + ((j == 0) ? 1 : 0);
        }
        mod1[i] = BigMod(n, 2 * k, k);
        for (var j = 0; j < 2 * k; j++) {
            mod1[i].a[j] <== mul1[i].out[j];
        }
        for (var j = 0; j < k; j++) {
            mod1[i].b[j] <== c[j];
        }
        for (var j = 0; j < k; j++) {
            partial[i + 1][j] <== mod1[i].out[j];
        }
        
        // now store the square of the previous power in powers[i+1]
        if (i < exp_bits - 1) {
            mul2[i] = BigMult(n, k, k);
            for (var j = 0; j < k; j++) {
                mul2[i].a[j] <== powers[i][j];
                mul2[i].b[j] <== powers[i][j];
            }
            mod2[i] = BigMod(n, 2 * k, k);
            for (var j = 0; j < 2 * k; j++) {
                mod2[i].a[j] <== mul2[i].out[j];
            }
            for (var j = 0; j < k; j++) {
                mod2[i].b[j] <== c[j];
            }
            for (var j = 0; j < k; j++) {
                powers[i + 1][j] <== mod2[i].out[j];
            }
        }
    }

    for (var i = 0; i < k; i++) {
        out[i] <== partial[exp_bits][i];
    }

}

template GroupVerify(size, n, k, exp_bits) {
    signal input sig[k];
    signal input e[size][exp_bits];
    signal input N[size][k];
    signal input message[k];
    signal input index;

    component muxE = Multiplexer(exp_bits, size);
    component muxN = Multiplexer(k, size);

    for (var i = 0; i < size; i++) {
        for (var j = 0; j < exp_bits; j++) {
            muxE.inp[i][j] <== e[i][j];
        }
        for (var j = 0; j < k; j++) {
            muxN.inp[i][j] <== N[i][j];
        }
    }
    muxE.sel <== index;
    muxN.sel <== index;

    component exp = BigModExp(n, k, exp_bits);
    
    for (var j = 0; j < k; j++) {
        exp.a[j] <== sig[j];
        exp.c[j] <== muxN.out[j];
    }
    for (var j = 0; j < exp_bits; j++) {
        exp.b[j] <== muxE.out[j];
    }
    for (var j = 0; j < k; j++) {
        message[j] === exp.out[j];
    }
}


template Main() {
    signal output out;
}
//a = 23
//b = 11
//c = 97

component main {public [e, N, message]} = GroupVerify(3, 64, 50, 17);

/* INPUT = {
    "sig": ["1", "1", "0"],
    "e": [
        ["1", "0", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        ["1", "1", "0", "0", "0", "0", "0", "0", "0", "0", "0", "0"],
        ["1", "0", "0", "1", "0", "0", "0", "0", "0", "0", "0", "0"] 
    ],
    "N": [
        ["1", "1", "1"],
        ["1", "0", "1"],
        ["1", "1", "0"] 
    ],
    "message": ["1", "0", "1"],
    "index": "0"
} */

