{
    val _minBoxValue: Long = 1000000L
    val _minerFee: Long = 1000000L
    val _txOperatorFee: Long = 1000000L

    val stateSingletonTokenId: Coll[Byte] = SELF.tokens(0)._1
    val isSale: Boolean = (INPUTS.size > 1)

    if (isSale) {
        val validSaleTx: Boolean = {
            val stateBoxIN: Box         = INPUTS(0)
            val buyerProxyIN: Box       = INPUTS(1)
            val nftIssuerOUT: Box       = OUTPUTS(0)
            val stateBoxOUT: Box        = OUTPUTS(1)
            val amountLP: Long          = SELF.R5[Long].get
            val isLastSale: Boolean     = (amountLP - 1L == 0L)
            val userFeeOUT: Box         = OUTPUTS(2)
            val liliumFeeOUT: Box       = OUTPUTS(3)
            val minerFeeOUT: Box        = if (isLastSale) OUTPUTS(4) else OUTPUTS(5)
            val txOperatorFeeOUT: Box   = if (isLastSale) OUTPUTS(5) else OUTPUTS(6)

            val validStateBox: Boolean = {
                (stateBoxIN.tokens(0)._1 == stateSingletonTokenId)
            }

            val validSelfRecreation: Boolean = {
                if (isLastSale) {
                    val validStateSingletonTokenBurn: Boolean = {
                        val outputTokenAmount: Long = OUTPUTS.flatMap({ (output: Box) =>
                            output.tokens.map({ (t: (Coll[Byte], Long)) =>
                                if (t._1 == stateSingletonTokenId) t._2 else 0L
                            })
                        }).fold(0L, { (acc: Long, curr: Long) => acc + curr })
                        (outputTokenAmount < 2L)
                    }
                    validStateSingletonTokenBurn
                } else {
                    val saleLPOUT: Box = OUTPUTS(4)
                    val minerFee = minerFeeOUT.value
                    val liliumFee = liliumFeeOUT.value
                    val fundsToSpend = _minBoxValue + minerFee + liliumFee + _txOperatorFee + minerFee
                    allOf(Coll(
                        (saleLPOUT.R5[Long].get == amountLP - 1L),
                        (saleLPOUT.value == SELF.value - fundsToSpend),
                        (saleLPOUT.propositionBytes == SELF.propositionBytes),
                        (saleLPOUT.tokens == SELF.tokens)
                    ))
                }
            }

            allOf(Coll(
                validStateBox,
                validSelfRecreation
            ))
        }
        sigmaProp(validSaleTx)
    } else {
        val artistSigmaProp: SigmaProp = SELF.R4[SigmaProp].get
        val validRefundTx: Boolean = {
            val userBox: Box = OUTPUTS(0)
            val minerBox: Box = OUTPUTS(1)
            val validUserBox: Boolean = {
                allOf(Coll(
                    (userBox.value == SELF.value - _minerFee),
                    (userBox.propositionBytes == artistSigmaProp.propBytes)
                ))
            }
            val validMinerFee: Boolean = (minerBox.value == _minerFee)
            val validSingletonBurn: Boolean = OUTPUTS.forall({(output: Box) => (output.tokens.size == 0)})
            allOf(Coll(
                validUserBox,
                validMinerFee,
                validSingletonBurn
            ))
        }
        sigmaProp(validRefundTx) && artistSigmaProp
    }
}
