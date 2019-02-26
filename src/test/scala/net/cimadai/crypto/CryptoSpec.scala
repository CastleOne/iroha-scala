package net.cimadai.crypto

import utest._

object CryptoSpec extends TestSuite {
  import scala.util.{Success, Failure}
  import net.cimadai.crypto.SHA3EdDSAKeyPair

  val tests = this {
    "SHA3EdDSAKeyPair should match a known, valid, existing key pair"-{
      val privateKey = "c84de08c2d9729b5c48d7dbd7b4b6e9db96ea7211cab9081e61c961f09cb8850cc54fecb3739db6294f46a7c909bf20fe554f85231ac490f7a907154b45f5d31"
      val publicKey  = "06d63d317d685b5f045706165122bd09cffd2397bf722615a6c7241e687a59a8"

      SHA3EdDSAKeyPair(privateKey) match {
        case Success(keypair) =>
          val actual = keypair.publicKey.toPublicKeyHex
          val expected = publicKey
          assert(actual == expected)
        case Failure(t) => throw t
      }
    }
  }

}
