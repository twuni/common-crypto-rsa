package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

import org.twuni.common.crypto.InputLengthException;

abstract class BlockTransformer extends org.twuni.common.crypto.BlockTransformer<BigInteger, BigInteger> {

	protected final BigInteger modulus;

	protected BlockTransformer( BigInteger modulus ) {
		this.modulus = modulus;
	}

	@Override
	protected BigInteger read( byte [] input ) {

		int blockSize = getInputBlockSize();

		if( input.length > blockSize ) {
			throw new InputLengthException( String.format( "Input length %s cannot be greater than block size %s.", Integer.valueOf( input.length ), Integer.valueOf( blockSize ) ) );
		}

		return new BigInteger( 1, input );

	}

}
