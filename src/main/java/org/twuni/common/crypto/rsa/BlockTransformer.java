package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

import org.twuni.common.crypto.InputLengthException;

abstract class BlockTransformer extends org.twuni.common.crypto.BlockTransformer<BigInteger, BigInteger> {

	protected final BigInteger modulus;

	protected BlockTransformer( BigInteger modulus ) {
		this.modulus = modulus;
	}

	protected BigInteger read( byte [] buffer, int offset, int length ) {

		if( length > getInputBlockSize() ) {
			throw new InputLengthException( String.format( "Length %s cannot be greater than the block size %s.", Integer.valueOf( length ), Integer.valueOf( getInputBlockSize() ) ) );
		}

		byte [] block = buffer;

		if( offset != 0 || length != buffer.length ) {
			block = new byte [length];
			System.arraycopy( buffer, offset, block, 0, length );
		}

		BigInteger result = new BigInteger( 1, block );

		if( result.compareTo( modulus ) >= 0 ) {
			throw new InputLengthException( String.format( "Result %s cannot be greater than or equal to modulus %s.", result, modulus ) );
		}

		return result;

	}

}
