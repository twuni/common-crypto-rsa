package org.twuni.common.crypto.rsa;

import static org.twuni.common.util.ByteArrayUtils.padLeft;
import static org.twuni.common.util.ByteArrayUtils.trim;

import java.math.BigInteger;

class BlockEncryptor extends BlockTransformer {

	public BlockEncryptor( BigInteger modulus ) {
		super( modulus );
	}

	@Override
	public int getInputBlockSize() {
		return getOutputBlockSize() - 1;
	}

	@Override
	public int getOutputBlockSize() {
		return ( modulus.bitLength() + 7 ) / 8;
	}

	@Override
	protected byte [] write( BigInteger input ) {
		int blockSize = getOutputBlockSize();
		return padLeft( trim( input.toByteArray() ), blockSize );
	}

}
