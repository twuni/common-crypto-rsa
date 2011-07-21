package org.twuni.common.crypto.rsa;

import static org.twuni.common.util.ByteArrayUtils.trim;

import java.math.BigInteger;

class BlockDecryptor extends BlockTransformer {

	public BlockDecryptor( BigInteger modulus ) {
		super( modulus );
	}

	@Override
	public int getInputBlockSize() {
		return ( modulus.bitLength() + 7 ) / 8;
	}

	@Override
	public int getOutputBlockSize() {
		return getInputBlockSize() - 1;
	}

	@Override
	protected byte [] write( BigInteger input ) {
		return trim( input.toByteArray() );
	}

}
