package net.cimadai.crypto

import utest._

object CryptoSpec extends TestSuite {

  val tests = this {
    "Ability to generate a random KeyPair"- {
      for {
        context <- SHA3EdDSAContext.apply
        keypair <- SHA3EdDSAKeyPair.random(context)
      } yield {
        val hexaPrivateKey = keypair.privateKey.hexa
        val hexaPublicKey  = keypair.publicKey.hexa

        println("1234567890123456789012345678901234567890123456789012345678901234")
        println(hexaPrivateKey)
        println(hexaPublicKey)

        assert(hexaPrivateKey.length == 64)
        assert(hexaPublicKey.length == 64)
        assert(hexaPrivateKey.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        assert(hexaPublicKey .forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
      }
    }

    "SHA3EdDSAKeyPair should match a known, valid, existing key pair"- {
      val givenPrivateKey = "FD3E07032D62B932C5CDDDAFC242AC6E4A4573DC7A00B38312BDB22C5B6F957D".toLowerCase
      val givenPublicKey  = "A447BDA11CC533D7804FDCF3D5E70832AAA795BDFA1F114F7D7992219DFF3FA1".toLowerCase
      for {
        context    <- SHA3EdDSAContext.apply
        keypair    <- SHA3EdDSAKeyPair   .apply(givenPrivateKey)(context)
        privateKey <- SHA3EdDSAPrivateKey.apply(givenPrivateKey)(context)
        publicKey  <- SHA3EdDSAPublicKey .apply(givenPublicKey)(context)
      } yield {
        val hexaPrivateKey = privateKey.hexa
        val hexaPublicKey  = publicKey.hexa

        println("1234567890123456789012345678901234567890123456789012345678901234")
        println(hexaPrivateKey)
        println(hexaPublicKey)

        assert(hexaPrivateKey.length == 64)
        assert(hexaPublicKey.length == 64)
        assert(hexaPrivateKey.forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
        assert(hexaPublicKey .forall(c => (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))

        assert(hexaPrivateKey == givenPrivateKey)
        assert(hexaPublicKey  == givenPublicKey)
        assert(keypair.privateKey.hexa == givenPrivateKey)
        assert(keypair.publicKey.hexa  == givenPublicKey)
      }
    }

    "SHA3EdDSAKeyPair should should be able to sign and verify messages"- {
      val givenPrivateKey = "FD3E07032D62B932C5CDDDAFC242AC6E4A4573DC7A00B38312BDB22C5B6F957D".toLowerCase
      val givenPublicKey  = "A447BDA11CC533D7804FDCF3D5E70832AAA795BDFA1F114F7D7992219DFF3FA1".toLowerCase
      for {
        context    <- SHA3EdDSAContext.apply
        keypair    <- SHA3EdDSAKeyPair.apply(givenPrivateKey)(context)
      } yield {
        import scala.util.Success
        import scala.util.Failure
        val message = "This is a test message"
        keypair.privateKey.sign(message) match {
          case Success(signature) =>
            keypair.publicKey.verify(signature, message) match {
              case Success(verified) => assert(verified)
              case Failure(t) => throw t
            }
          case Failure(t) => throw t
        }
      }
    }
  }
}
