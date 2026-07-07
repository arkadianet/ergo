{
    val _tokenId = fromBase16("0000000000000000000000000000000000000000000000000000000000000001")
    val borrowerPK          = SELF.R5[SigmaProp].get
    val repayment           = SELF.R6[Long].get
    val maturityHeight      = SELF.R7[Int].get
    val lenderPK            = SELF.R8[SigmaProp].get
    val collateralAssets    = SELF.tokens
    val collateralERG       = SELF.value
    val repaymentBox        = OUTPUTS(0)

    if(HEIGHT >= maturityHeight){
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
      sigmaProp(liquidated)
    }else{
        val returnBox           = OUTPUTS(1)
        val repaid = {
            allOf(
                Coll(
                    repaymentBox.propositionBytes   == lenderPK.propBytes,
                    repaymentBox.value              == 1000000L,
                    repaymentBox.tokens(0)._1       == _tokenId,
                    repaymentBox.tokens(0)._2       == repayment,
                    repaymentBox.tokens.size        == 1,
                    repaymentBox.R4[Coll[Byte]].get == SELF.id,
                    returnBox.propositionBytes      == borrowerPK.propBytes,
                    returnBox.tokens                == collateralAssets,
                    returnBox.value                 == collateralERG
                )
            )
        }
        (sigmaProp(repaid) && borrowerPK)
      }
}
