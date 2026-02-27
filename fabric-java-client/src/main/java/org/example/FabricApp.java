package org.example;

import org.hyperledger.fabric.client.Contract;
import org.hyperledger.fabric.client.Gateway;
import org.hyperledger.fabric.client.Network;
import org.hyperledger.fabric.client.identity.Identities;
import org.hyperledger.fabric.client.identity.Identity;
import org.hyperledger.fabric.client.identity.Signer;
import org.hyperledger.fabric.client.identity.Signers;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.Files;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;

public class FabricApp {

    private static final String CHANNEL_NAME = "mychannel";
    private static final String CHAINCODE_NAME = "basic";

    public static void main(String[] args) throws Exception {

        // Paths
        Path networkConfigPath = Paths.get("connection-org1.yaml");
        Path certPath = Paths.get("crypto/org1/cert.pem");
        Path keyPath = Paths.get("crypto/org1/key.pem");

        // Load X.509 certificate
        X509Certificate certificate = Identities.readX509Certificate(
                Files.newBufferedReader(certPath)
        );

        // Load private key
        PrivateKey privateKey = Identities.readPrivateKey(
                Files.newBufferedReader(keyPath)
        );

        // Create identity and signer
        Identity identity = new Identity("Org1MSP", certificate);
        Signer signer = Signers.newPrivateKeySigner(privateKey);

        // Connect to gateway
        Gateway.Builder builder = Gateway.newInstance()
                .identity(identity)
                .signer(signer)
                .networkConfig(networkConfigPath);

        try (Gateway gateway = builder.connect()) {

            System.out.println("✅ Connected to Fabric Gateway");

            Network network = gateway.getNetwork(CHANNEL_NAME);
            Contract contract = network.getContract(CHAINCODE_NAME);

            // ---- INVOKE TRANSACTION ----
            System.out.println("\n▶ Submitting CreateAsset transaction...");
            contract.submitTransaction(
                    "CreateAsset",
                    "asset100",
                    "blue",
                    "20",
                    "Allenzo",
                    "1000"
            );
            System.out.println("✔ Asset created successfully");

            // ---- QUERY TRANSACTION ----
            System.out.println("\n▶ Querying asset asset100...");
            byte[] result = contract.evaluateTransaction("ReadAsset", "asset100");
            System.out.println("Asset details: " + new String(result));

            // ---- QUERY ALL ASSETS ----
            System.out.println("\n▶ Querying all assets...");
            byte[] allAssets = contract.evaluateTransaction("GetAllAssets");
            System.out.println("All assets: " + new String(allAssets));
        }
    }
}