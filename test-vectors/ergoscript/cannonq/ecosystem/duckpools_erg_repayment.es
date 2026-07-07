{
    val transactionFee = 1000000L
    val MaxBorrowTokens = 9000000000000000L
    val PoolNft = fromBase58("Ahk13GiqmS1txRpk9TdJmbs1Qr6wGya8MstvhMVfNDbq")

    val initalPool = INPUTS(0)
    val finalPool = OUTPUTS(0)

    val loanAmount = SELF.tokens(0)._2

    val borrow0 = MaxBorrowTokens - initalPool.tokens(2)._2
    val borrow1 = MaxBorrowTokens - finalPool.tokens(2)._2
    val deltaBorrowed = borrow0 - borrow1

    val validFinalPool = finalPool.tokens(0)._1 == PoolNft
    val validInitialPool = initalPool.tokens(0)._1 == PoolNft

    val deltaValue = finalPool.value - initalPool.value

    val validValue = deltaValue >= SELF.value - transactionFee
    val validBorrowed = deltaBorrowed == loanAmount

    val multiBoxSpendSafety = INPUTS(1) == SELF

    sigmaProp(
        validFinalPool &&
        validInitialPool &&
        validValue &&
        validBorrowed &&
        multiBoxSpendSafety
    )
}
