let circuit = null;
let provingKey = null;
let verifyingKey = null;
let publicKeysList = [];

// Convert input to field element format for the circuit
function inputToFieldElement(input) {
    if (typeof input === 'string') {
        if (input.startsWith('0x')) {
            return BigInt(input).toString();
        } else {
            // Treat as regular integer
            return BigInt(input).toString();
        }
    } else {
        return BigInt(input).toString();
    }
}

// Utility function to convert a big number to an array of 64-bit chunks
function bigIntTo64BitChunks(bigNum, numChunks) {
    const chunks = [];
    const mask = BigInt("0xFFFFFFFFFFFFFFFF"); // 64-bit mask
    let remaining = BigInt(bigNum);
    
    for (let i = 0; i < numChunks; i++) {
        chunks.push(Number(remaining & mask));
        remaining = remaining >> BigInt(64);
    }
    
    return chunks;
}

// Utility function to convert a big number to an array of bits
function bigIntToBits(bigNum, numBits) {
    const bits = [];
    let remaining = BigInt(bigNum);
    
    for (let i = 0; i < numBits; i++) {
        bits.push(Number(remaining & BigInt(1)));
        remaining = remaining >> BigInt(1);
    }
    
    return bits;
}

async function setupCircuit() {
    const publicKeysInput = document.getElementById('publicKeys').value;
    const setupOutput = document.getElementById('setupOutput');
    
    try {
        setupOutput.innerHTML = 'Setting up circuit...';
        
        // Parse public keys (format: "e1,n1;e2,n2;...")
        const keyPairs = publicKeysInput.split(';').map(pair => pair.trim());
        publicKeysList = keyPairs.map(pair => {
            const [e, n] = pair.split(',').map(k => k.trim());
            if (!e || !n) throw new Error('Invalid public key format');
            return { e, n };
        });
        if (publicKeysList.length === 0) {
            throw new Error('Please provide at least one public key pair');
        }
        
        // Load circuit files
        setupOutput.innerHTML = 'Loading circuit files...';
        
        try {
            // Load the compiled circuit
            const circuitResponse = await fetch('./rsa_big_js/rsa_big.wasm');
            if (!circuitResponse.ok) {
                throw new Error('Failed to load circuit WASM file. Make sure to run the setup first.');
            }
            circuit = await circuitResponse.arrayBuffer();
            
            // Load proving key
            const provingKeyResponse = await fetch('./rsa_big_0000.zkey');
            if (!provingKeyResponse.ok) {
                throw new Error('Failed to load proving key. Make sure to run the setup first.');
            }
            provingKey = await provingKeyResponse.arrayBuffer();
            
            // Load verifying key
            const verifyingKeyResponse = await fetch('./verification_key.json');
            if (!verifyingKeyResponse.ok) {
                throw new Error('Failed to load verifying key. Make sure to run the setup first.');
            }
            verifyingKey = await verifyingKeyResponse.json();
            
        } catch (fetchError) {
            setupOutput.innerHTML = `
                <div class="error">Circuit files not found. Please run setup first:</div>
                <div>1. npm install</div>
                <div>2. npm run setup</div>
                <div>Error: ${fetchError.message}</div>
            `;
            return;
        }
        
        setupOutput.innerHTML = `
            <div class="success">Circuit setup complete!</div>
            <div>Public key pairs: ${publicKeysList.length}</div>
            <div>Circuit loaded and ready to generate proofs</div>
            <div>Note: The circuit will verify that the signature is valid for one of the provided public key pairs</div>
        `;
        
    } catch (error) {
        setupOutput.innerHTML = `<div class="error">Setup failed: ${error.message}</div>`;
    }
}

async function generateProof() {
    const signature = document.getElementById('signature').value;
    const message = document.getElementById('message').value;
    const proofOutput = document.getElementById('proofOutput');
    
    if (publicKeysList.length === 0) {
        proofOutput.innerHTML = '<div class="error">Please setup the circuit first</div>';
        return;
    }
    
    if (!circuit || !provingKey) {
        proofOutput.innerHTML = '<div class="error">Circuit not loaded. Please run setup first.</div>';
        return;
    }
    
    try {
        proofOutput.innerHTML = 'Generating proof...';
        
        // Constants for the circuit
        const K = 3; // Number of 64-bit chunks for signature and modulus
        const N = 64; // Number of bits per chunk for exponent
        
        // Convert signature to 64-bit chunks
        const signatureChunks = bigIntTo64BitChunks(signature, K);
        
        // Convert message to 64-bit chunks
        const messageChunks = bigIntTo64BitChunks(message, K);
        
        // Convert public keys to appropriate format
        const eArrays = publicKeysList.map(key => {
            const eBits = bigIntToBits(key.e, N * K);
            return eBits;
        });
        
        const nArrays = publicKeysList.map(key => {
            return bigIntTo64BitChunks(key.n, K);
        });
        
        // Ensure we have exactly 3 public key pairs for the circuit
        const paddedPublicKeys = [...publicKeysList];
        while (paddedPublicKeys.length < 3) {
            paddedPublicKeys.push(paddedPublicKeys[paddedPublicKeys.length - 1]);
        }
        if (paddedPublicKeys.length > 3) {
            paddedPublicKeys.length = 3;
        }
        
        const circuitInputs = {
            sig: signatureChunks,
            e: eArrays.slice(0, 3),
            N: nArrays.slice(0, 3),
            message: messageChunks
        };
        
        console.log('Circuit inputs:', circuitInputs);
        
        proofOutput.innerHTML = 'Computing witness and generating proof...';
        
        // Generate the full proof
        const { proof, publicSignals } = await snarkjs.groth16.fullProve(
            circuitInputs,
            "./rsa_big_js/rsa_big.wasm",
            "./rsa_big_0000.zkey"
        );
        
        const fullProof = {
            proof: proof,
            publicSignals: publicSignals
        };
        
        proofOutput.innerHTML = `
            <div class="success">Proof generated successfully!</div>
            <div><strong>Proof size:</strong> ${JSON.stringify(proof).length} bytes</div>
            <div><strong>Public signals:</strong> ${publicSignals.length}</div>
            <div><strong>Proof:</strong></div>
            <pre>${JSON.stringify(fullProof, null, 2)}</pre>
        `;
        
        // Auto-fill the verify section
        document.getElementById('proofJson').value = JSON.stringify(fullProof, null, 2);
        
    } catch (error) {
        proofOutput.innerHTML = `<div class="error">Proof generation failed: ${error.message}</div>`;
        console.error('Detailed error:', error);
    }
}

async function verifyProof() {
    const proofJson = document.getElementById('proofJson').value;
    const verifyOutput = document.getElementById('verifyOutput');
    
    if (!verifyingKey) {
        verifyOutput.innerHTML = '<div class="error">Verifying key not loaded. Please run setup first.</div>';
        return;
    }
    
    try {
        verifyOutput.innerHTML = 'Verifying proof...';
        
        const proofData = JSON.parse(proofJson);
        
        if (!proofData.proof || !proofData.publicSignals) {
            throw new Error('Invalid proof format - missing proof or publicSignals');
        }
        
        verifyOutput.innerHTML = 'Performing cryptographic verification...';
        
        // Verify the cryptographic proof using snarkjs
        const isValidProof = await snarkjs.groth16.verify(
            verifyingKey,
            proofData.publicSignals,
            proofData.proof
        );
        
        if (isValidProof) {
            // Additional check: verify that the public signals match the expected inputs
            // Public signals format: [e[0], e[1], e[2], e[3], e[4], n[0], n[1], n[2], n[3], n[4], message]
            // Note: signature is now private and not in public signals
            const expectedMessage = inputToFieldElement(document.getElementById('message').value);
            
            // Extract expected e and n arrays (padded to 5)
            const paddedKeys = [...publicKeysList];
            while (paddedKeys.length < 5) {
                paddedKeys.push(paddedKeys[paddedKeys.length - 1]);
            }
            if (paddedKeys.length > 5) {
                paddedKeys.length = 5;
            }
            const expectedE = paddedKeys.map(k => inputToFieldElement(k.e));
            const expectedN = paddedKeys.map(k => inputToFieldElement(k.n));
            
            // Compare public signals (no signature anymore)
            const publicSignals = proofData.publicSignals.map(s => s.toString());
            const actualE = publicSignals.slice(0, 5);
            const actualN = publicSignals.slice(5, 10);
            const actualMessage = publicSignals[10];
            
            const inputsMatch = 
                actualMessage === expectedMessage &&
                actualE.every((e, i) => e === expectedE[i]) &&
                actualN.every((n, i) => n === expectedN[i]);
            
            if (inputsMatch) {
                verifyOutput.innerHTML = `
                    <div class="success">✓ Proof verified successfully!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✓ Public signals match expected inputs</div>
                    <div>The prover has a valid RSA signature for the message using one of the provided public keys.</div>
                    <div><strong>Message:</strong> ${actualMessage}</div>
                    <div><em>Note: The signature remains private and is not revealed in the proof.</em></div>
                `;
            } else {
                verifyOutput.innerHTML = `
                    <div class="error">✗ Proof verification failed!</div>
                    <div>✓ Cryptographic proof is valid</div>
                    <div>✗ Public signals don't match expected inputs</div>
                    <div>The proof may be for different signature/message/keys.</div>
                `;
            }
        } else {
            verifyOutput.innerHTML = `
                <div class="error">✗ Proof verification failed!</div>
                <div>✗ Cryptographic proof is invalid</div>
                <div>The proof does not satisfy the circuit constraints.</div>
            `;
        }
        
    } catch (error) {
        verifyOutput.innerHTML = `<div class="error">Verification failed: ${error.message}</div>`;
        console.error('Detailed verification error:', error);
    }
}

// Helper function to generate some example public keys for testing
function generateExampleKeys() {
    // Example from the circuit comment
    const exampleKeys = '77,12827;10,12827';
    
    document.getElementById('publicKeys').value = exampleKeys;
    document.getElementById('signature').value = '3';
    document.getElementById('message').value = '5566';
    console.log('Example RSA keys and values loaded from circuit comment');
}

// Initialize with example data
window.onload = function() {
    generateExampleKeys();
};