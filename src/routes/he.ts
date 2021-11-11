import express from 'express'
import {
  CreatePKEModule, PKEModule,
  CryptoContext_DCRTPoly, Ciphertext_DCRTPoly,Plaintext
} from 'palisade-crypto'




export class HE{
  public  router = express.Router();

  static inputs = [
    [1,2,3,4,5,6,7,8,9,10,11,12],
    [3,2,1,4,5,6,7,8,9,10,11,12],
    [1,2,5,2,5,6,7,8,9,10,11,12]
  ];
  static rotationIndices = [1,2,-1,-2];
  static createCryptoContext(module: PKEModule): CryptoContext_DCRTPoly {
    // Set the main parameters
    const plaintextModulus = 65537;
    const sigma = 3.2;
    const depth = 2;

    const cryptoContext = module.GenCryptoContextBFVrns(
        plaintextModulus, module.SecurityLevel.HEStd_128_classic,
        sigma, 0, depth, 0, module.MODE.OPTIMIZED);

    cryptoContext.Enable(module.PKESchemeFeature.ENCRYPTION);
    cryptoContext.Enable(module.PKESchemeFeature.SHE);
    return cryptoContext;
  }
  constructor() {

    this.router.route('/')
        .get(function (req, res) {
          CreatePKEModule().then( module => {
            console.log('creating crypto context')
            const cryptoContext = HE.createCryptoContext(module);
            console.log('generating keypair')
            const keyPair = cryptoContext.KeyGen();
            console.log('generating evaluation keys')
            // multiplication and rotation keys must be generated ahead of time
            cryptoContext.EvalMultKeyGen(keyPair.secretKey)
            cryptoContext.EvalAtIndexKeyGen(
                keyPair.secretKey, HE.rotationIndices);

            console.log('encrypting inputs to ciphertexts')
            const vectors = HE.inputs.map( array => module.MakeVectorInt64Clipped(array));
            const plaintexts = vectors.map(
                vector => cryptoContext.MakePackedPlaintext(vector)
            );
            const ciphertexts = plaintexts.map(
                plaintext => cryptoContext.EncryptPublic(keyPair.publicKey, plaintext)
            );

            const ciphertextAdd12 =
                cryptoContext.EvalAddCipherCipher(ciphertexts[0], ciphertexts[1]);
            const ciphertextAddResult =
                cryptoContext.EvalAddCipherCipher(ciphertextAdd12, ciphertexts[2]);

            const ciphertextMul12 =
                cryptoContext.EvalMultCipherCipher(ciphertexts[0], ciphertexts[1]);
            // type annotations work! (and are enforced)
            const ciphertextMulResult: Ciphertext_DCRTPoly =
                cryptoContext.EvalMultCipherCipher(ciphertextMul12, ciphertexts[2]);

            const ciphertextRotations = HE.rotationIndices.map(
                index => cryptoContext.EvalAtIndex(ciphertexts[0],index)
            );

            const plaintextAddResult =
                cryptoContext.Decrypt(keyPair.secretKey, ciphertextAddResult);
            const plaintextMultResult =
                cryptoContext.Decrypt(keyPair.secretKey, ciphertextMulResult);
            const plaintextRotations: Plaintext[] = ciphertextRotations.map(
                ciphertext => cryptoContext.Decrypt(keyPair.secretKey, ciphertext)
            );
            for (const plaintext of plaintextRotations) {
              plaintext.SetLength(HE.inputs[0].length);
            }

            console.log(`Plaintext #1: ${plaintexts[0]}`);
            console.log(`Plaintext #2: ${plaintexts[1]}`);
            console.log(`Plaintext #3: ${plaintexts[2]}`);
            console.log("\nResults of homomorphic computations");
            console.log(`#1 + 2 + #3: ${plaintextAddResult}`)
            console.log(`#1 * 2 * #3: ${plaintextMultResult}`)
            console.log(`Left rotation of #1 by 1: ${plaintextRotations[0]}`);
            console.log(`Left rotation of #1 by 2: ${plaintextRotations[1]}`);
            console.log(`Right rotation of #1 by 1: ${plaintextRotations[2]}`);
            console.log(`Right rotation of #1 by 2: ${plaintextRotations[3]}`);
          });

        });


  }



}
