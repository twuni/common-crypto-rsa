package org.twuni.common.crypto.rsa;

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

		byte [] output = input.toByteArray();
		int blockSize = getOutputBlockSize();

		if( output.length > blockSize ) {
			byte [] buffer = new byte [blockSize];
			System.arraycopy( output, output.length - blockSize, buffer, 0, buffer.length );
			return buffer;
		}

		if( output.length < blockSize ) {
			byte [] buffer = new byte [blockSize];
			System.arraycopy( output, 0, buffer, buffer.length - output.length, output.length );
			return buffer;
		}

		return output;

	}

}
