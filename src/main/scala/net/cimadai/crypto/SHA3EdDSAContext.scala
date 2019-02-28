package net.cimadai.crypto

import acyclic.pkg

sealed trait SHA3EdDSAContext {
  import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec
  import jp.co.soramitsu.crypto.ed25519.{Ed25519Sha3, EdDSAEngine}
  import org.spongycastle.jcajce.provider.digest.SHA3.DigestSHA3
  val digest: DigestSHA3
  val engine: EdDSAEngine
  val crypto: Ed25519Sha3
  val spec: EdDSAParameterSpec
}
object SHA3EdDSAContext {
  import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec
  import jp.co.soramitsu.crypto.ed25519.{Ed25519Sha3, EdDSAEngine}
  import org.spongycastle.jcajce.provider.digest.SHA3.DigestSHA3
  import scala.util.Try

  private case class impl(digest: DigestSHA3,
                          engine: EdDSAEngine,
                          crypto: Ed25519Sha3,
                          spec: EdDSAParameterSpec) extends SHA3EdDSAContext

  def apply: Try[SHA3EdDSAContext] = Try {
    import org.spongycastle.jcajce.provider.digest.SHA3
    val digest: DigestSHA3  = new SHA3.Digest256
    val engine: EdDSAEngine = new EdDSAEngine(digest)
    val crypto: Ed25519Sha3 = new Ed25519Sha3()
    val spec: EdDSAParameterSpec = Ed25519Sha3.spec
    impl(digest, engine, crypto, spec)
  }
}
