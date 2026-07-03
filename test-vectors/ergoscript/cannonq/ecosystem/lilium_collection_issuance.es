{
    val _txOperatorPK = proveDlog(decodePoint(fromBase16("02d04baf1e643c82e9e25f35a8636e1c4ae9bfc12944af9c8dd9b6a47fd7f8b700")))

    val StateBoxContractBytes: Coll[Byte] = getVar[Coll[Byte]](0).get
    val CollectionIssuerBox: Box = getVar[Box](1).get

    val properOutput = (OUTPUTS(0).propositionBytes == StateBoxContractBytes)
    val properTokenTransfer = (OUTPUTS(0).tokens(1) == (CollectionIssuerBox.id, CollectionIssuerBox.R9[Long].get)) && (SELF.tokens(0)._1  == CollectionIssuerBox.id)

    sigmaProp(properOutput && properTokenTransfer) && _txOperatorPK
}
