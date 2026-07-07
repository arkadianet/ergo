{
    val borrowerPK          = SELF.R5[SigmaProp].get
    val repayment           = SELF.R6[Long].get
    val maturityHeight      = SELF.R7[Int].get
    val lenderPK            = SELF.R8[SigmaProp].get
    val hashedLiqScript     = SELF.R9[Coll[Byte]].get
    val collateralAssets    = SELF.tokens
    val collateralERG       = SELF.value
    val repaymentBox        = OUTPUTS(0)

    val liquidationScript   = getVar[SigmaProp](0)

    val liquidationConditions = {
      if(liquidationScript.isDefined){
        val matchedHash = blake2b256( liquidationScript.get.propBytes ) == hashedLiqScript
        sigmaProp(matchedHash) && liquidationScript.get
      }else{
        sigmaProp(HEIGHT >= maturityHeight)
      }
    }
    val liquidated = {
        allOf(
            Coll(
                repaymentBox.propositionBytes   == lenderPK.propBytes,
                repaymentBox.tokens             == collateralAssets,
                repaymentBox.value              == collateralERG,
                repaymentBox.R4[Coll[Byte]].get == SELF.id
            )
        )
    }
    val returnBox           = OUTPUTS(1)
    val repaid = {
        allOf(
            Coll(
                HEIGHT < maturityHeight,
                repaymentBox.propositionBytes   == lenderPK.propBytes,
                repaymentBox.value              == repayment,
                repaymentBox.R4[Coll[Byte]].get == SELF.id,
                returnBox.propositionBytes      == borrowerPK.propBytes,
                returnBox.tokens                == collateralAssets,
                returnBox.value                 == collateralERG
            )
        )
    }

    (sigmaProp(liquidated) && liquidationConditions) || (sigmaProp(repaid) && borrowerPK)
}
