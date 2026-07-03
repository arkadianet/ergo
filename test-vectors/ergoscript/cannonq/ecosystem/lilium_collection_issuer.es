{
    val _txOperatorPK = proveDlog(decodePoint(fromBase16("02d04baf1e643c82e9e25f35a8636e1c4ae9bfc12944af9c8dd9b6a47fd7f8b700")))

    val collectionIssuanceContractBytes: Coll[Byte] = getVar[Coll[Byte]](0).get

    val nftBox = (OUTPUTS(0).tokens(0) == (SELF.id, SELF.R9[Long].get))
    val properOutput = (OUTPUTS(0).propositionBytes == collectionIssuanceContractBytes)

    sigmaProp(nftBox && properOutput) && _txOperatorPK
}
