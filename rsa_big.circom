pragma circom 2.1.6;

include "node_modules/circomlib/circuits/poseidon.circom";
// include "node_modules/circomlib/circuits/bitify.circom";
include "bigint_func.circom";
include "bigint.circom";
// include "circomlib/poseidon.circom";
// include "circomlib/bitify.circom";




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

template BigModExp (n, k) {
    // outputs a**b mod c, where b is expressed AS AN ARRAY OF BITS 
    signal input a[k];
    signal input b[n * k];
    signal input c[k];
    signal output out[k];

    component mod1[n * k];
    component mod2[n * k];
    component mul1[n * k];
    component mul2[n * k];

    signal partial[n * k + 1][k];
    signal powers[n * k][k];
    partial[0][0] <== 1;
    for (var i = 0; i < k; i++) {
        powers[0][i] <== a[i];
        if (i > 0) {
            partial[0][i] <== 0;
        }
    }
    // powers[0] <== a;

    for (var i = 0; i < n * k; i++) {
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
        if (i < n * k - 1) {
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
        out[i] <== partial[n * k][i];
    }

}

template GroupVerify(size, n, k) {
    signal input sig[k];
    signal input e[size][n * k];
    signal input N[size][k];
    signal input message[k];

    component exp[size];
    component add[size];
    component mul[size];
    signal differences[size][k];

    for (var i = 0; i < size; i++) {
        exp[i] = BigModExp(n, k);
        for (var j = 0; j < k; j++) {
            exp[i].a[j] <== sig[j];
            exp[i].c[j] <== N[i][j];
        }
        for (var j = 0; j < n * k; j++) {
            exp[i].b[j] <== e[i][j];
        }
        for (var l = 0; l < k; l++) {
            differences[i][l] <== exp[i].out[l] - message[l];
        }
    }

    signal inv[size][k];
    signal z[size][k];
    signal temp[size][k];
    signal accum[size][k+1];
    for (var i = 0; i < size; i++) {
        for (var j = 0; j < k; j++) {
            inv[i][j] <-- (differences[i][j] == 0) ? 1 : 0;
            z[i][j] <-- (differences[i][j] == 0) ? 0 : 1/differences[i][j];
            temp[i][j] <== z[i][j] * differences[i][j];

            0 === inv[i][j] * differences[i][j];
            (inv[i][j] - 1) * (temp[i][j] - 1) === 0;
            (inv[i][j] - 1) * inv[i][j] === 0;
            accum[i][j] <== (j == 0) ? 1 : accum[i][j - 1] * inv[i][j];
        }
        accum[i][k] <== (i == 0) ? (accum[0][k-1] - 1) : accum[i - 1][k] * (accum[i][k-1] - 1);
    }
    accum[size - 1][k] === 0;
}


template Main() {
    signal output out;
}
//a = 23
//b = 11
//c = 97

component main = GroupVerify(3, 4, 3);

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
    "message": ["1", "0", "1"]
} */

