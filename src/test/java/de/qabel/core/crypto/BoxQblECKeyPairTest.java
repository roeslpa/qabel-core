package de.qabel.core.crypto;

import org.junit.Test;
import org.spongycastle.util.encoders.Hex;
import static org.junit.Assert.*;

public class BoxQblECKeyPairTest {
	@Test
	public void rootRefCalculationTest() {
		CryptoUtils cu = new CryptoUtils();
		BoxQblECKeyPair testKey = new BoxQblECKeyPair(Hex.decode("99624a656a002c61a0a66d21901df76021d887477af99b3d467921c00e6ff705"));

		String DMindexName = testKey.getRootRef("b5911736-9ace-a799-8e34-dd9c17acff9a");

		assertEquals(DMindexName, "9a60ca51-c696-9bc6-03e6-d762eab07ecb");
	}
}
