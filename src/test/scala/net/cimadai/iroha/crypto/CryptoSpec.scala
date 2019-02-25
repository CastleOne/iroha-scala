package net.cimadai.iroha.crypto

import utest._

object CryptoSpec extends TestSuite {
  import scala.util.{Success, Failure}
  import net.cimadai.crypto.SHA3EdDSAKeyPair

  val tests = this {
    "SHA3EdDSAKeyPair should match a known, valid, existing key pair"-{
      val privateKey = "f101537e319568c765b2cc89698325604991dca57b9716b58016b253506cab70"
      val publicKey  = "313a07e6384776ed95447710d15e59148473ccfc052a681317a72a69f2a49910"
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
