{
    val _txOperatorPK = proveDlog(decodePoint(fromBase16("02d04baf1e643c82e9e25f35a8636e1c4ae9bfc12944af9c8dd9b6a47fd7f8b700")))

    val validWhitelistMintTx: Boolean = {
        val validWhitelistIssuanceBox: Boolean = {
            val whitelistAmount = SELF.R4[Long].get
            val userPk = SELF.R5[SigmaProp].get
            val validTokens: Boolean = (OUTPUTS(0).tokens(0) == (SELF.id, whitelistAmount))
            val validUser: Boolean = (OUTPUTS(0).propositionBytes == userPk.propBytes)
            allOf(Coll(
                validTokens,
                validUser
            ))
        }
        validWhitelistIssuanceBox
    }

    sigmaProp(validWhitelistMintTx) && _txOperatorPK
}
