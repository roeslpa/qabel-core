package de.qabel.core.crypto;

import org.spongycastle.crypto.digests.SHA256Digest;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.UUID;

public class BoxQblECKeyPair extends QblECKeyPair {
	public BoxQblECKeyPair(byte[] privateKey) {
		super(privateKey);
	}
	public BoxQblECKeyPair() {
		super();
	}
	/**
	 * Calculates the name of the index DM for a given prefix
	 * @param prefix Name of the prefix
	 * @return Name of the index DM
	 */
	public String getRootRef(String prefix) {
		SHA256Digest md = new SHA256Digest();
		byte[] digest = new byte[md.getDigestSize()];
		md.update(prefix.getBytes(), 0, prefix.getBytes().length);
		md.update(this.getPrivateKey(), 0, KEY_SIZE_BYTE);
		md.doFinal(digest, 0);
		byte[] firstBytes = Arrays.copyOfRange(digest, 0, 16);
		ByteBuffer bb = ByteBuffer.wrap(firstBytes);
		UUID uuid = new UUID(bb.getLong(), bb.getLong());
		return uuid.toString();
	}
}
