package org.twuni.common.crypto.rsa;

import java.io.IOException;
import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.twuni.common.crypto.Base64;

public class TransformerTest {

	private Transformer trusted;
	private Transformer untrusted;

	@Before
	public void setUp() {
		PrivateKey privateKey = new KeyGenerator().generate( 512 );
		PublicKey publicKey = privateKey.getPublicKey();
		trusted = new Transformer( privateKey );
		untrusted = new Transformer( publicKey );
	}

	@Test
	public void testMultipleBlockRoundTripString() throws IOException {

		String expected = generateRandomString( 4096 );
		String actual = decrypt( encrypt( expected ) );

		Assert.assertEquals( expected, actual );

	}

	@Test
	public void testMultipleBlockRoundTripTwoLayersString() throws IOException {

		String expected = generateRandomString( 4096 );
		String actual = decrypt( decrypt( encrypt( encrypt( expected ) ) ) );

		Assert.assertEquals( expected, actual );

	}

	@Test
	public void testMultipleBlockRoundTripBytes() throws IOException {

		byte [] expected = generateRandomBytes( 4096 );
		byte [] actual = decrypt( encrypt( expected ) );

		Assert.assertArrayEquals( expected, actual );

	}

	@Test
	public void testMultipleBlockRoundTripTwoLayersBytes() throws IOException {

		byte [] expected = generateRandomBytes( 4096 );
		byte [] actual = decrypt( decrypt( encrypt( encrypt( expected ) ) ) );

		Assert.assertArrayEquals( expected, actual );

	}

	private byte [] decrypt( byte [] message ) throws IOException {
		return untrusted.decrypt( message );
	}

	private byte [] encrypt( byte [] message ) throws IOException {
		return trusted.encrypt( message );
	}

	private String decrypt( String message ) throws IOException {
		return untrusted.decrypt( message );
	}

	private String encrypt( String message ) throws IOException {
		return trusted.encrypt( message );
	}

	private String generateRandomString( int length ) {
		return Base64.encode( generateRandomBytes( length * 2 ) ).substring( 0, length );
	}

	private byte [] generateRandomBytes( int length ) {
		Random random = new Random();
		byte [] buffer = new byte [length];
		random.nextBytes( buffer );
		return buffer;
	}

}
