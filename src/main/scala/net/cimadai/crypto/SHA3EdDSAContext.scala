package net.cimadai.crypto

sealed trait SHA3EdDSAContext {
  import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec
  import jp.co.soramitsu.crypto.ed25519.{Ed25519Sha3, EdDSAEngine}
  val engine: EdDSAEngine
  val crypto: Ed25519Sha3
  val spec: EdDSAParameterSpec
}
object SHA3EdDSAContext {
  import jp.co.soramitsu.crypto.ed25519.spec.EdDSAParameterSpec
  import jp.co.soramitsu.crypto.ed25519.{Ed25519Sha3, EdDSAEngine}
  import scala.util.Try

  private case class impl(engine: EdDSAEngine, crypto: Ed25519Sha3, spec: EdDSAParameterSpec) extends SHA3EdDSAContext

  def apply: Try[SHA3EdDSAContext] = Try {
    import jp.co.soramitsu.crypto.ed25519.EdDSAEngine
    import org.spongycastle.jcajce.provider.digest.SHA3
    val engine: EdDSAEngine = new EdDSAEngine(new SHA3.Digest256)
    val crypto: Ed25519Sha3 = new Ed25519Sha3()
    val spec: EdDSAParameterSpec = Ed25519Sha3.spec
    impl(engine, crypto, spec)
  }
}
