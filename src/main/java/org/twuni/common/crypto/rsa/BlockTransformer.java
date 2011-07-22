package org.twuni.common.crypto.rsa;

import java.math.BigInteger;

abstract class BlockTransformer extends org.twuni.common.crypto.BlockTransformer<BigInteger, BigInteger> {

	protected final BigInteger modulus;

	protected BlockTransformer( BigInteger modulus ) {
		this.modulus = modulus;
	}

	@Override
	protected BigInteger read( byte [] input ) {
		return new BigInteger( 1, input );
	}

}
