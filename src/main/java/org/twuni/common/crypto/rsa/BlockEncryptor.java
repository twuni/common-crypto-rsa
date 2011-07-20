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
	protected byte [] write( BigInteger result ) {

		byte [] output = result.toByteArray();

		if( output[0] == 0 && output.length > getOutputBlockSize() ) {
			byte [] buffer = new byte [getOutputBlockSize()];
			System.arraycopy( output, 1, buffer, 0, buffer.length );
			return buffer;
		}

		if( output.length < getOutputBlockSize() ) {
			byte [] buffer = new byte [getOutputBlockSize()];
			System.arraycopy( output, 0, buffer, buffer.length - output.length, output.length );
			return buffer;
		}

		return output;

	}

}
