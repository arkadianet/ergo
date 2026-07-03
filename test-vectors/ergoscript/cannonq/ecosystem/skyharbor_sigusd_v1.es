{
if (OUTPUTS.size > 2) {
val currency = fromBase58("GYATox71P9XAERmzoDdTGELa62f5ALyjxJLRSfJfKsh")
val serviceGets = max((SELF.R4[Long].get / 50),1L)
val royaltyBox = SELF.R6[Box].get
val purchaseNFT = if (royaltyBox.R4[Int].isDefined) {
val royalty = royaltyBox.R4[Int].get
val royaltyGets = if(royalty != 0) {max((SELF.R4[Long].get * royalty / 1000),1L)} else {0L}
val sellerGets = SELF.R4[Long].get - serviceGets - royaltyGets
allOf(Coll(
OUTPUTS(0).tokens(0)._2 >= sellerGets,
OUTPUTS(0).tokens(0)._1 == currency,
OUTPUTS(0).propositionBytes == SELF.R5[Coll[Byte]].get,
OUTPUTS(0).R4[Coll[Byte]].get == SELF.id,
OUTPUTS(1).tokens(0)._1 == currency,
OUTPUTS(1).tokens(0)._2 >= serviceGets,
OUTPUTS(1).propositionBytes == fromBase58("1sw5t6iJRxzSjNGvSRw8kcaTADxEG52wGMVgSjdXPLMbhvUM"),
OUTPUTS(2).tokens(0)._1 == currency,
if (royaltyGets != 0) {OUTPUTS(2).tokens(0)._2 >= royaltyGets && OUTPUTS(2).propositionBytes == royaltyBox.propositionBytes} else{true},
royaltyBox.id == SELF.tokens(0)._1))
} else {
val sellerGets = SELF.R4[Long].get - serviceGets
allOf(Coll(
OUTPUTS(0).tokens(0)._2 >= sellerGets,
OUTPUTS(0).tokens(0)._1 == currency,
OUTPUTS(0).propositionBytes == SELF.R5[Coll[Byte]].get,
OUTPUTS(0).R4[Coll[Byte]].get == SELF.id,
OUTPUTS(1).tokens(0)._1 == currency,
OUTPUTS(1).tokens(0)._2 >= serviceGets,
OUTPUTS(1).propositionBytes == fromBase58("1sw5t6iJRxzSjNGvSRw8kcaTADxEG52wGMVgSjdXPLMbhvUM"),
royaltyBox.id == SELF.tokens(0)._1))
}
sigmaProp(purchaseNFT) } else {
val pubKey = SELF.R7[GroupElement].get
proveDlog(pubKey)
}
}
