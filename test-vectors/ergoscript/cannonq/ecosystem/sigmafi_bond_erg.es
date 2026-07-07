{
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
                  repaymentBox.value              == repayment,
                  repaymentBox.R4[Coll[Byte]].get == SELF.id,
                  returnBox.propositionBytes      == borrowerPK.propBytes,
                  returnBox.tokens                == collateralAssets,
                  returnBox.value                 == collateralERG
              )
          )
      }

      sigmaProp(repaid) && borrowerPK
  }
}
