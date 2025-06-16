package digests;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class MessageDigestWrapper {

    private final MessageDigest md;

    /*
     * Given the hashing algorithm, sets the md variable to be an instance of MessageDigest.
     * Total suggested lines: 1.
     */
    public MessageDigestWrapper(String algorithm) throws NoSuchAlgorithmException {
        this.md = MessageDigest.getInstance(algorithm);
    }

    /*
     * Given an array of bytes, updates the input buffer and computes the digest.
     * Total suggested lines: 2.
     */
    public byte[] computeDigest(byte[] input) {
        this.md.update(input);
        return this.md.digest();
    }

    /*
     * Given a byte, this method computes its digest.
     * Total suggested lines: 1.
     */
    public byte[] computeDigest(byte input) {
        this.md.update(input);
        return this.md.digest();
    }

}