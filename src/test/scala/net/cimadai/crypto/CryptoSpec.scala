package net.cimadai.crypto

import utest._

object CryptoSpec extends TestSuite {
  import scala.util.{Success, Failure}
  import net.cimadai.crypto.SHA3EdDSAKeyPair

  val tests = this {
    "SHA3EdDSAKeyPair should match a known, valid, existing key pair"-{
      val privateKey = "FD3E07032D62B932C5CDDDAFC242AC6E4A4573DC7A00B38312BDB22C5B6F957D"
      val publicKey  = "A447BDA11CC533D7804FDCF3D5E70832AAA795BDFA1F114F7D7992219DFF3FA1"
      SHA3EdDSAKeyPair(privateKey) match {
        case Success(keypair) =>
          val actual = keypair.publicKey.toPublicKeyHex
          val expected = publicKey
          assert(actual == expected)
        case Failure(t) => throw t
      }
    }
    "SHA3EdDSAKeyPair should generate a random, valid key pair"-{
      SHA3EdDSAKeyPair.random match {
        case Success(keypair) =>
          val privateKey = keypair.privateKey.toPrivateKeyHex
          val publicKey  = keypair.publicKey.toPublicKeyHex
          assert(privateKey.length == 32)
          assert(publicKey.length  == 32)
          SHA3EdDSAKeyPair(privateKey) match {
            case Success(keypair) =>
              assert(keypair.privateKey.toPrivateKeyHex == privateKey)
              assert(keypair.publicKey.toPublicKeyHex   == publicKey)
            case Failure(t) => throw t
          }
        case Failure(t) => throw t
      }
    }
  }

}
