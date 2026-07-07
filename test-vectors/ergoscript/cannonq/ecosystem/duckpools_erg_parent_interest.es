{
    val MaximumExecutionFee = 5000000L
    val ChildExecutionFee = 2000000L
    val InterestContractDenomination = 100000000L
    val MaxHistorySize = 430

    val currentScript = SELF.propositionBytes
    val currentValue = SELF.value
    val currentParentToken = SELF.tokens(0)
    val currentChildTokens = SELF.tokens(1)
    val currentInterestHistory = SELF.R4[Coll[Long]].get

    val successor = OUTPUTS(0)
    val successorScript = successor.propositionBytes
    val successorValue = successor.value
    val successorParentToken = successor.tokens(0)
    val successorChildTokens = successor.tokens(1)
    val successorInterestHistory = successor.R4[Coll[Long]].get

    val headChild = CONTEXT.dataInputs(0)
    val headChildScript = headChild.propositionBytes
    val headChildToken = headChild.tokens(0)
    val headInterestHistory = headChild.R4[Coll[Long]].get
    val headChildHeight = headChild.R5[Long].get
    val headIndex = headChild.R6[Int].get

    val newChild = OUTPUTS(1)
    val newChildScript = newChild.propositionBytes
    val newChildValue = newChild.value
    val newChildToken = newChild.tokens(0)
    val newInterestHistory = newChild.R4[Coll[Long]].get
    val newChildHeight = newChild.R5[Long].get
    val newIndex = newChild.R6[Int].get

    val validSuccessorScript = successorScript == currentScript
    val validSuccessorValue = successorValue >= currentValue - MaximumExecutionFee - (MaxHistorySize * ChildExecutionFee)
    val retainParentToken = successorParentToken == currentParentToken
    val validChildTokensId = successorChildTokens._1 == currentChildTokens._1
    val validChildTokensAmount = successorChildTokens._2 == currentChildTokens._2 - 1
    val noMoreTokens = successor.tokens.size == SELF.tokens.size
    val validDummyRegisters = (
        successor.R5[Boolean].get &&
        successor.R6[Boolean].get &&
        successor.R7[Boolean].get &&
        successor.R8[Boolean].get &&
        successor.R9[Boolean].get
    )

    val totalInterestAccrued = headInterestHistory.fold(InterestContractDenomination, {(z:Long, base:Long) => (z * base / InterestContractDenomination)})
    val validSuccessorInterestHistory = (
        currentInterestHistory.append(Coll(totalInterestAccrued)) == successorInterestHistory
    )

    val validHeaderTokenId = headChildToken._1 == currentChildTokens._1
    val validHeaderIndex = headIndex == currentInterestHistory.size
    val validHeaderHistorySize = headInterestHistory.size >= MaxHistorySize

    val validChildScript = newChildScript == headChildScript
    val validChildValue = newChildValue >= MaxHistorySize * ChildExecutionFee
    val validChildToken = newChildToken == headChildToken
    val validChildIndex = newIndex == successorInterestHistory.size
    val validChildHistory = newInterestHistory == Coll(InterestContractDenomination)
    val validChildHeight = newChildHeight == headChildHeight
    val validChildDummyRegisters = (
        newChild.R7[Boolean].get &&
        newChild.R8[Boolean].get &&
        newChild.R9[Boolean].get
    )
    val validChildTokenSize = newChild.tokens.size == 1

    sigmaProp(
        validSuccessorScript &&
        validSuccessorValue &&
        retainParentToken &&
        validChildTokensId &&
        validChildTokensAmount &&
        validSuccessorInterestHistory &&
        noMoreTokens &&
        validDummyRegisters &&
        validHeaderTokenId &&
        validHeaderIndex &&
        validHeaderHistorySize &&
        validChildScript &&
        validChildValue &&
        validChildToken &&
        validChildIndex &&
        validChildHistory &&
        validChildHeight &&
        validChildDummyRegisters &&
        validChildTokenSize
    )
}
