package de.qabel.core.crypto;

import org.spongycastle.crypto.digests.SHA256Digest;

import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.UUID;

/**
 * Elliptic curve key pair
 */
public class QblECKeyPair implements Serializable {

	public static final int KEY_SIZE_BYTE = 32;

	private Curve25519 curve25519;
	private byte[] privateKey;
	private QblECPublicKey pubKey;

	/**
	 * Creates an elliptic curve key pair with a given private key
	 * @param privateKey
	 *            private key which is used to calculate public point
	 */
	public QblECKeyPair(byte[] privateKey) {

		curve25519 = new Curve25519();

		this.privateKey = privateKey;
		this.pubKey = new QblECPublicKey(curve25519.cryptoScalarmultBase(this.privateKey));
	}

	/**
	 * Generates an elliptic curve key pair with a random private key
	 */
	public QblECKeyPair() {
		this(generatePrivateKey());
	}

	/**
	 * Generates a random Curve25519 private key.
	 * @return random private key
	 */
	static private byte[] generatePrivateKey(){
		SecureRandom random = new SecureRandom();
		byte[] randomBytes = new byte[KEY_SIZE_BYTE];
		random.nextBytes(randomBytes);

		return randomBytes;
	}

	/**
	 * Elliptic curve diffie hellman which generates a shared secret.
	 *
	 * @param contactsPubKey
	 *            Public key of contact
	 * @return shared secret between A and B
	 */
	public byte[] ECDH(QblECPublicKey contactsPubKey) {
		return curve25519.cryptoScalarmult(privateKey, contactsPubKey.getKey());
	}

	/**
	 * Get public part of key pair
	 *
	 * @return public part of key pair
	 */
	public QblECPublicKey getPub() {
		return pubKey;
	}

	// TODO: Shift all usages of the private key to this class and export the key only password protected
	public byte[] getPrivateKey() {
		return privateKey;
	}

	@Override
	public boolean equals(Object o) {
		if(this == o) { return true; }
		if(o == null || getClass() != o.getClass()) { return false; }

		QblECKeyPair ecKeyPair = (QblECKeyPair) o;

		if(!Arrays.equals(privateKey, ecKeyPair.privateKey)) { return false; }
		if(!pubKey.equals(ecKeyPair.pubKey)) { return false; }

		return true;
	}

	@Override
	public int hashCode() {
		int result = Arrays.hashCode(privateKey);
		result = 31 * result + pubKey.hashCode();
		return result;
	}
}
