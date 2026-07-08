/**
 * Eight SigmaProp params — the recon's p8 discriminator; includes the
 * zeta/bravo and delta/beta root-bucket collisions.
 */
@contract def gate8h(sigma: SigmaProp, delta: SigmaProp, kappa: SigmaProp, omega: SigmaProp, theta: SigmaProp, gamma: SigmaProp, lambda: SigmaProp, beta: SigmaProp) = sigma && delta && kappa && omega && theta && gamma && lambda && beta
