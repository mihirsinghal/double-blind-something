const snarkjs = require("snarkjs");
const fs = require("fs");
const { execSync } = require('child_process');

async function setup() {
    console.log("Starting trusted setup...");
    
    try {
        // Check if circom is available
        try {
            execSync('circom --version', { stdio: 'pipe' });
        } catch (e) {
            console.error("Circom not found. Please install circom first:");
            console.error("Visit: https://docs.circom.io/getting-started/installation/");
            return;
        }
        
        // Compile the circuit
        console.log("Compiling circuit...");
        execSync('circom rsa_small.circom --r1cs --wasm --sym', { stdio: 'inherit' });
        
        // Download powers of tau if not exists
        console.log("Checking powers of tau file...");
        if (!fs.existsSync("./powersOfTau28_hez_final_10.ptau")) {
            console.log("Downloading powers of tau (this may take a while)...");
            try {
                execSync('curl -L -o powersOfTau28_hez_final_10.ptau https://storage.googleapis.com/zkevm/ptau/powersOfTau28_hez_final_10.ptau', { stdio: 'inherit' });
            } catch (error) {
                console.log("Primary download failed, trying alternative...");
                execSync('curl -L -o powersOfTau28_hez_final_10.ptau https://github.com/iden3/snarkjs/raw/master/powersOfTau28_hez_final_10.ptau', { stdio: 'inherit' });
            }
        }
        
        // Generate proving and verifying keys
        console.log("Generating proving and verifying keys...");
        await snarkjs.zKey.newZKey(
            "rsa_small.r1cs",
            "powersOfTau28_hez_final_10.ptau",
            "rsa_small_0000.zkey"
        );
        
        // Export verifying key
        console.log("Exporting verifying key...");
        const vKey = await snarkjs.zKey.exportVerificationKey("rsa_small_0000.zkey");
        fs.writeFileSync("verification_key.json", JSON.stringify(vKey, null, 2));
        
        console.log("\n✅ Setup complete!");
        console.log("Files generated:");
        console.log("- rsa_small.wasm (in rsa_small_js/ directory)");
        console.log("- rsa_small_0000.zkey");
        console.log("- verification_key.json");
        console.log("\nYou can now run: npm run serve");
        
    } catch (error) {
        console.error("Setup failed:", error.message);
        console.error("\nTroubleshooting:");
        console.error("1. Make sure circom is installed: https://docs.circom.io/getting-started/installation/");
        console.error("2. Check that your circuit file is valid");
    }
}

setup();