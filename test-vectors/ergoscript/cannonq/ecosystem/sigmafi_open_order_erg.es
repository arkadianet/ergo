{
    val _bondContractHash = fromBase16("0000000000000000000000000000000000000000000000000000000000000001")
    val _devPK = proveDlog(decodePoint(fromBase16("02d04baf1e643c82e9e25f35a8636e1c4ae9bfc12944af9c8dd9b6a47fd7f8b700")))

    val borrowerPK      = SELF.R4[SigmaProp].get
    val principal       = SELF.R5[Long].get
    val repayment       = SELF.R6[Long].get
    val maturityLength  = SELF.R7[Int].get
    val totalAssets     = SELF.tokens
    val totalERG        = SELF.value

    val bondBox         = OUTPUTS(0)
    val orderIsClosed   = _bondContractHash == blake2b256( bondBox.propositionBytes )

    val optUIFee        = getVar[SigmaProp](0)

    val fees: Coll[(SigmaProp, BigInt)] = {
        val feeDenom = 100000L
        val devFee   = 500L
        if(optUIFee.isDefined){
            val uiFee = 400L
            Coll(
                 (_devPK, (devFee.toBigInt * principal.toBigInt) / feeDenom.toBigInt),
                 (optUIFee.get, (uiFee.toBigInt * principal.toBigInt) / feeDenom.toBigInt)
            )
        }else{
            Coll( (_devPK, (devFee.toBigInt * principal.toBigInt) / feeDenom.toBigInt) )
        }
    }

    if(orderIsClosed){
        val loanBox     = OUTPUTS(1)
        val orderMade   = {
            allOf(
                Coll(
                    bondBox.R4[Coll[Byte]].get == SELF.id,
                    bondBox.R5[SigmaProp].get  == borrowerPK,
                    bondBox.R6[Long].get       == repayment,
                    bondBox.R8[SigmaProp].isDefined,
                    bondBox.tokens             == totalAssets,
                    bondBox.value              == totalERG,
                    maturityLength             >= 30,
                    (HEIGHT + maturityLength) - bondBox.R7[Int].get <= 8,
                    (HEIGHT + maturityLength) - bondBox.R7[Int].get >= 0,
                    loanBox.propositionBytes   == borrowerPK.propBytes,
                    loanBox.value              == principal
                )
            )
        }

        val feesPaid = {
            val devFeesPaid = {
                if(fees(0)._2 > 0){
                    val devOutput   = OUTPUTS(2)
                    allOf(
                        Coll(
                            devOutput.propositionBytes   == fees(0)._1.propBytes,
                            devOutput.value.toBigInt     == fees(0)._2
                        )
                    )
                }else{
                    true
                }
            }
            val uiFeesPaid = {
                if(optUIFee.isDefined){
                    if(fees(1)._2 > 0){
                        val uiOutput    = OUTPUTS(3)
                        allOf(
                            Coll(
                                uiOutput.propositionBytes   == fees(1)._1.propBytes,
                                uiOutput.value.toBigInt     == fees(1)._2
                            )
                        )
                    }else{
                        true
                    }
                }else{
                    true
                }
            }
            devFeesPaid && uiFeesPaid
        }

        sigmaProp(orderMade && feesPaid)
    }else{
        borrowerPK
    }
}
