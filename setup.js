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
        execSync('circom rsa_big.circom --r1cs --wasm --sym', { stdio: 'inherit' });
        
        // Download powers of tau if not exists (need larger file for RSA circuit)
        console.log("Checking powers of tau file...");
        const ptauFile = "powersOfTau28_hez_final_22.ptau";
        if (!fs.existsSync(`./${ptauFile}`)) {
            console.log("Downloading powers of tau (this may take a while - ~200MB)...");
            try {
                execSync(`curl -L -o ${ptauFile} https://storage.googleapis.com/zkevm/ptau/${ptauFile}`, { stdio: 'inherit' });
            } catch (error) {
                console.log("Primary download failed, trying hermez...");
                execSync(`curl -L -o ${ptauFile} https://hermez.s3-eu-west-1.amazonaws.com/${ptauFile}`, { stdio: 'inherit' });
            }
        }
        
        // Generate proving and verifying keys
        console.log("Generating proving and verifying keys...");
        await snarkjs.zKey.newZKey(
            "rsa_big.r1cs",
            ptauFile,
            "rsa_big_0000.zkey"
        );
        
        // Export verifying key
        console.log("Exporting verifying key...");
        const vKey = await snarkjs.zKey.exportVerificationKey("rsa_big_0000.zkey");
        fs.writeFileSync("verification_key.json", JSON.stringify(vKey, null, 2));
        
        console.log("\n✅ Setup complete!");
        console.log("Files generated:");
        console.log("- rsa_big.wasm (in rsa_big_js/ directory)");
        console.log("- rsa_big_0000.zkey");
        console.log("- verification_key.json");
        console.log("\nYou can now run: npm run serve");
        
    } catch (error) {
        console.error("Setup failed:", error);
    }
}

setup();