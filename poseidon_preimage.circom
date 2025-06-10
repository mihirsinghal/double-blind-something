pragma circom 2.0.0;

include "circomlib/poseidon.circom";

template PoseidonPreimage(n) {
    signal input preimage;
    signal input validHashes[n];
    signal output validHashesOut[n];
    
    component hasher = Poseidon(1);
    hasher.inputs[0] <== preimage;
    
    signal product;
    signal differences[n];
    signal partialProducts[n];
    
    for (var i = 0; i < n; i++) {
        differences[i] <== hasher.out - validHashes[i];
        validHashesOut[i] <== validHashes[i];  // Output the valid hashes as public signals
    }
    
    partialProducts[0] <== differences[0];
    for (var i = 1; i < n; i++) {
        partialProducts[i] <== partialProducts[i-1] * differences[i];
    }
    
    product <== partialProducts[n-1];
    product === 0;
}

component main = PoseidonPreimage(5);