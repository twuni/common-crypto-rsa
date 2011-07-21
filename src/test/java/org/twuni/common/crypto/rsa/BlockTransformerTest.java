package org.twuni.common.crypto.rsa;

import java.util.Random;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.twuni.common.crypto.InputLengthException;
import org.twuni.common.util.Base64;
import org.twuni.common.util.ByteArrayUtils;

public class BlockTransformerTest {

	private static final int BLOCK_SIZE = 128;

	private KeyGenerator keygen;

	@Before
	public void setUp() {
		keygen = new KeyGenerator();
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthMatchesBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE ) );
	}

	@Test( expected = InputLengthException.class )
	public void testSingleBlockEncryptionFailsWhenInputLengthIsMoreThanBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE - 8 ) );
	}

	@Test
	public void testSingleBlockRoundTripSucceedsWhenInputLengthIsLessThanBlockSize() {
		assertRoundTrip( keygen.generate( BLOCK_SIZE + 8 ) );
	}

	@Test
	public void testSingleBlockRoundTripWithBytesSucceedsWhenInputLengthMatchesBlockSize() {
		assertRoundTripBytes( keygen.generate( BLOCK_SIZE ) );
	}

	@Test( expected = InputLengthException.class )
	public void testSingleBlockEncryptionWithBytesFailsWhenInputLengthIsMoreThanBlockSize() {
		assertRoundTripBytes( keygen.generate( BLOCK_SIZE - 8 ) );
	}

	@Test
	public void testSingleBlockRoundTripWithBytesSucceedsWhenInputLengthIsLessThanBlockSize() {
		assertRoundTripBytes( keygen.generate( BLOCK_SIZE + 8 ) );
	}

	private void assertRoundTrip( PrivateKey privateKey ) {
		assertRoundTripFromPrivateKey( privateKey );
		assertRoundTripFromPublicKey( privateKey );
	}

	private void assertRoundTripBytes( PrivateKey privateKey ) {
		assertRoundTripBytesFromPrivateKey( privateKey );
		assertRoundTripBytesFromPublicKey( privateKey );
	}

	private void assertRoundTripFromPrivateKey( PrivateKey privateKey ) {
		byte [] expected = generateRandomString( BLOCK_SIZE / 8 - 1 ).getBytes();
		assertRoundTripFromPrivateKey( privateKey, expected );
	}

	private void assertRoundTripBytesFromPrivateKey( PrivateKey privateKey ) {
		byte [] expected = generateRandomBytes( BLOCK_SIZE / 8 - 1 );
		assertRoundTripFromPrivateKey( privateKey, expected );
	}

	private void assertRoundTripFromPublicKey( PrivateKey privateKey ) {
		byte [] expected = generateRandomString( BLOCK_SIZE / 8 - 1 ).getBytes();
		assertRoundTripFromPublicKey( privateKey, expected );
	}

	private void assertRoundTripBytesFromPublicKey( PrivateKey privateKey ) {
		byte [] expected = generateRandomBytes( BLOCK_SIZE / 8 - 1 );
		assertRoundTripFromPublicKey( privateKey, expected );
	}

	private void assertRoundTripFromPrivateKey( PrivateKey privateKey, byte [] expected ) {
		byte [] actual = roundTrip( privateKey, privateKey.getPublicKey(), expected );
		assertArrayEquals( expected, actual );
	}

	private void assertRoundTripFromPublicKey( PrivateKey privateKey, byte [] expected ) {
		byte [] actual = roundTrip( privateKey.getPublicKey(), privateKey, expected );
		assertArrayEquals( expected, actual );
	}

	protected void assertArrayEquals( byte [] expected, byte [] actual ) {
		Assert.assertArrayEquals( expected, ByteArrayUtils.trim( actual ) );
	}

	private byte [] roundTrip( PublicKey from, PrivateKey to, byte [] message ) {

		BlockEncryptor encryptor = new BlockEncryptor( from.getModulus() );
		BlockDecryptor decryptor = new BlockDecryptor( from.getModulus() );

		byte [] encrypted = encryptor.transform( from, message );
		byte [] actual = decryptor.transform( to, encrypted );

		return actual;

	}

	private byte [] roundTrip( PrivateKey from, PublicKey to, byte [] message ) {

		BlockEncryptor encryptor = new BlockEncryptor( to.getModulus() );
		BlockDecryptor decryptor = new BlockDecryptor( to.getModulus() );

		byte [] encrypted = encryptor.transform( from, message );
		byte [] actual = decryptor.transform( to, encrypted );

		return actual;

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
