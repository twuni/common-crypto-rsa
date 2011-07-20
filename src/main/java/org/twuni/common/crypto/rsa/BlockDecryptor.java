package org.twuni.common.crypto.rsa;

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
	protected byte [] write( BigInteger result ) {

		byte [] output = result.toByteArray();

		if( output[0] == 0 ) {
			byte [] buffer = new byte [output.length - 1];
			System.arraycopy( output, 1, buffer, 0, buffer.length );
			return buffer;
		}

		return output;

	}

}
